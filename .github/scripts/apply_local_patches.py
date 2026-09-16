# LC32 fork-local compatibility patch set for legacy ARMv7 apps.
from pathlib import Path

source = Path("HostFrameworks/LC32/dynarmic_syscalls.cpp")
text = source.read_text()

include_anchor = '#include <poll.h>\n'
include_block = '#include <poll.h>\n#include <net/if.h>\n#include <sys/sockio.h>\n'
if '#include <sys/sockio.h>' not in text:
    if include_anchor not in text:
        raise SystemExit('include anchor not found')
    text = text.replace(include_anchor, include_block, 1)

helper_anchor = 'int guest_ioctl(int fildes, u32 request, u32 guest_r2) {\n'
helper_block = r'''/*
 * The armv7 SIOCGIFCONF request embeds an 8-byte struct ifconf whose pointer
 * is 32 bits wide (0xc0086924). The native process is arm64, so forwarding
 * that request or guest pointer directly would expose the wrong ABI to XNU.
 * Stage the payload in host memory, issue the native SIOCGIFCONF, and copy the
 * returned interface records back into the guest buffer.
 */
static constexpr u32 LC32_SIOCGIFCONF32 = 0xc0086924u;
static constexpr size_t LC32_MAXIMUM_IFCONF_BYTES = 1024 * 1024;

struct LC32Ifconf32 {
    int32_t ifc_len;
    u32 ifc_buf;
};

static_assert(sizeof(LC32Ifconf32) == 8,
    "armv7 ifconf ABI must remain 8 bytes");

static int guest_siocgifconf32(int fildes, u32 guest_arg) {
    if (guest_arg == 0) {
        return return_with_carry_direct(EFAULT, true);
    }

    LC32Ifconf32 guestIfconf{};
    if (!read_guest_memory_with_permissions(
            guest_arg, &guestIfconf, sizeof(guestIfconf), PROT_READ) ||
            !guest_memory_range_has_permissions(
                guest_arg, sizeof(guestIfconf), PROT_WRITE)) {
        return return_with_carry_direct(EFAULT, true);
    }
    if (guestIfconf.ifc_len < 0) {
        return return_with_carry_direct(EINVAL, true);
    }

    const size_t guestCapacity =
        static_cast<size_t>(guestIfconf.ifc_len);
    if (guestCapacity > LC32_MAXIMUM_IFCONF_BYTES) {
        return return_with_carry_direct(ENOMEM, true);
    }
    if (guestCapacity != 0) {
        if (guestIfconf.ifc_buf == 0 ||
                !guest_memory_range_has_permissions(
                    guestIfconf.ifc_buf, guestCapacity, PROT_WRITE)) {
            return return_with_carry_direct(EFAULT, true);
        }
    }

    std::vector<char> hostBuffer;
    try {
        hostBuffer.resize(std::max<size_t>(guestCapacity, 1));
    } catch (const std::bad_alloc &) {
        return return_with_carry_direct(ENOMEM, true);
    }

    struct ifconf hostIfconf{};
    hostIfconf.ifc_len = static_cast<int>(guestCapacity);
    hostIfconf.ifc_buf = guestCapacity != 0 ? hostBuffer.data() : nullptr;

    const int result = syscallRetCarry(
        SYS_ioctl, fildes, SIOCGIFCONF, &hostIfconf, 0, 0, 0, 0);
    if (threadHandle.cpsr->hasCarry()) {
        return result;
    }
    if (hostIfconf.ifc_len < 0) {
        return return_with_carry_direct(EIO, true);
    }

    const size_t returnedLength =
        static_cast<size_t>(hostIfconf.ifc_len);
    const size_t copyLength =
        std::min(returnedLength, guestCapacity);
    if (copyLength != 0 &&
            !write_guest_memory_with_permissions(
                guestIfconf.ifc_buf, hostBuffer.data(),
                copyLength, PROT_WRITE)) {
        return return_with_carry_direct(EFAULT, true);
    }
    if (returnedLength > static_cast<size_t>(INT32_MAX)) {
        return return_with_carry_direct(EOVERFLOW, true);
    }

    guestIfconf.ifc_len = static_cast<int32_t>(returnedLength);
    if (!write_guest_memory_with_permissions(
            guest_arg, &guestIfconf, sizeof(guestIfconf), PROT_WRITE)) {
        return return_with_carry_direct(EFAULT, true);
    }

    LC32_DEBUG_PRINTF(
        "LC32: SIOCGIFCONF32 fd=%d capacity=%zu returned=%zu\\n",
        fildes, guestCapacity, returnedLength);
    return result;
}

/*
 * The classic interface-query ioctls use a 32-byte ifreq on both the armv7
 * guest ABI and current Darwin arm64 ABI. Stage it anyway so the kernel never
 * receives a guest virtual address.
 */
static int guest_ifreq_ioctl(int fildes, u32 request, u32 guest_arg) {
    static constexpr size_t GuestIfreqSize = 32;
    static_assert(sizeof(struct ifreq) == GuestIfreqSize,
        "native Darwin ifreq layout changed");

    if (guest_arg == 0) {
        return return_with_carry_direct(EFAULT, true);
    }

    struct ifreq hostRequest{};
    if (!read_guest_memory_with_permissions(
            guest_arg, &hostRequest, sizeof(hostRequest), PROT_READ) ||
            !guest_memory_range_has_permissions(
                guest_arg, sizeof(hostRequest), PROT_WRITE)) {
        return return_with_carry_direct(EFAULT, true);
    }

    const int result = syscallRetCarry(
        SYS_ioctl, fildes, request, &hostRequest, 0, 0, 0, 0);
    if (threadHandle.cpsr->hasCarry()) {
        return result;
    }
    if (!write_guest_memory_with_permissions(
            guest_arg, &hostRequest, sizeof(hostRequest), PROT_WRITE)) {
        return return_with_carry_direct(EFAULT, true);
    }
    return result;
}

'''
if 'LC32_SIOCGIFCONF32' not in text:
    if helper_anchor not in text:
        raise SystemExit('guest_ioctl anchor not found')
    text = text.replace(helper_anchor, helper_block + helper_anchor, 1)

switch_anchor = '''        case FIODTYPE: {
'''
switch_block = '''        case LC32_SIOCGIFCONF32:
            return guest_siocgifconf32(fildes, guest_r2);
        case SIOCGIFFLAGS:
        case SIOCGIFADDR:
        case SIOCGIFDSTADDR:
        case SIOCGIFBRDADDR:
        case SIOCGIFNETMASK:
        case SIOCGIFMTU:
            return guest_ifreq_ioctl(fildes, request, guest_r2);
        case FIODTYPE: {
'''
if 'case LC32_SIOCGIFCONF32:' not in text:
    if switch_anchor not in text:
        raise SystemExit('ioctl switch anchor not found')
    text = text.replace(switch_anchor, switch_block, 1)

source.write_text(text)
print('Applied LC32 ARM32 network ioctl compatibility patch')
