#if !defined(NETCAP_ARP_PACKET_VIEW)
#define NETCAP_ARP_PACKET_VIEW

#include <span>
#include <netcap/exception.h>
#include <netcap/addr_ipv4.h>
#include <netcap/byte.h>
#include <netinet/in.h>

class ArpPacketView {
public:
    ArpPacketView(std::span<uint8_t> data) : d(data) {
        if (d.size() < 28)
            throw std::invalid_argument("invalid ARP/RARP packet");
    }

    uint16_t hardware_type() const noexcept {
        return ntohs(*(uint16_t *)(&d[0]));
    }

    uint16_t protocol_type() const noexcept {
        return ntohs(*(uint16_t *)(&d[2]));
    }

    uint8_t hardware_len() const noexcept {
        return d[4];
    }

    uint8_t protocol_len() const noexcept {
        return d[5];
    }

    uint16_t op() const noexcept {
        return ntohs(*(uint16_t *)(&d[6]));
    }

    std::span<uint8_t> sender_mac() const noexcept {
        return d.subspan(8, 6);
    }

    AddrIPv4 sender_ip() const noexcept {
        return AddrIPv4{*(uint32_t *)(&d[14])};
    }

    std::span<uint8_t> target_mac() const noexcept {
        return d.subspan(18, 6);
    }

    AddrIPv4 target_ip() const noexcept {
        return AddrIPv4{*(uint32_t *)(&d[24])};
    }

private:
    std::span<uint8_t> d;
};

#endif // NETCAP_ARP_PACKET_VIEW
