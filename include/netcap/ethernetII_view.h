#if !defined(NETCAP_ETHERNETII_INCLUDED)
#define NETCAP_ETHERNETII_INCLUDED

#include <netcap/byte.h>
#include <netinet/in.h>
#include <span>

class EthernetIIView {
public:
    enum { 
        ETH_ALEN = 6 
    };

    EthernetIIView(std::span<uint8_t> packet) : pack(packet) {}

    std::span<uint8_t> dmac() const noexcept {
        return pack.subspan(0, ETH_ALEN);
    }

    std::span<uint8_t> smac() const noexcept {
        return pack.subspan(ETH_ALEN, ETH_ALEN);
    }

    uint16_t type() const noexcept {
        return ntohs(*(uint16_t *)(pack.data() + ETH_ALEN * 2));
    }

    std::span<uint8_t> playload() const noexcept {
        return pack.subspan(ETH_ALEN * 2 + 2);
    }

    bool is_ipv4() const {
        return type() == 0x0800;
    }

    bool is_ipv6() const {
        return type() == 0x86DD;
    }

    bool is_arp() const {
        return type() == 0x0806;
    }

    bool is_rarp() const {
        return type() == 0x0835;
    }

    const char *type_string() const {
        switch (type()) {
        case 0x0800:
            return "IPv4";
        case 0x0806:
            return "ARP";
        case 0x0835:
            return "RARP";
        case 0x86DD:
            return "IPv6";
        default:
            return "";
        }
    }

private:
    std::span<uint8_t> pack;
};

#endif // NETCAP_ETHERNETII_INCLUDED
