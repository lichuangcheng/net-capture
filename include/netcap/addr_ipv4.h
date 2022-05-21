#if !defined(NETCAP_ADDR_IPV4_INCLUDED)
#define NETCAP_ADDR_IPV4_INCLUDED

#include <netinet/in.h>
#include <string>
#include <fmt/core.h>

struct AddrIPv4 : in_addr { 
    std::string to_string() const {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&s_addr);
        return fmt::format("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    }

    bool operator<(const AddrIPv4 &r) const noexcept {
        return s_addr < r.s_addr;
    }
};

#endif // NETCAP_ADDR_IPV4_INCLUDED
