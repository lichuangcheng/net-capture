#if !defined(NETCAP_IPV4_PACKET_VIEW_INCUDED)
#define NETCAP_IPV4_PACKET_VIEW_INCUDED

#include <netcap/addr_ipv4.h>
#include <netcap/protocol_type.h>
#include <span>

class IPv4PacketView {
public:
    IPv4PacketView(std::span<uint8_t> data) : data(data) {
        if (data.size() < 20)
            throw std::invalid_argument("invalid ipv4 packet data");
    }

    uint8_t version() const noexcept {
        return (data[0] >> 4) & 0xf;
    }

    uint8_t header_lenght() const noexcept {
        return (data[0] & 0xf) * 4;
    }

    uint8_t service_type() const noexcept {
        return data[1];
    }

    uint16_t total_lenght() const noexcept {
        return as_host<uint16_t>(&data[2]);
    }

    uint16_t identification() const noexcept {
        return as_host<uint16_t>(&data[4]);
    }

    uint8_t flags() const noexcept {
        return (data[6] >> 5) & 0b00000111;
    }

    uint16_t fragment_offset() const noexcept {
        return as_host<uint16_t>(&data[6]) & 0x1fff;
    }

    bool dont_fragment() const noexcept {
        return flags() & 0b0000'0010;
    }

    bool more_fragment() const noexcept {
        return flags() & 0b0000'0001;
    }

    uint8_t TTL() const noexcept {
        return data[8];
    }

    ProtocolType protocol() const noexcept {
        return (ProtocolType)data[9];
    }

    uint16_t header_checksum() const {
        return as_host<uint16_t>(&data[10]);
    }

    AddrIPv4 sender_ip() const noexcept {
        return AddrIPv4{as<uint32_t>(&data[12])};
    }

    AddrIPv4 target_ip() const noexcept {
        return AddrIPv4{as<uint32_t>(&data[16])};
    }

    std::span<uint8_t> playload() const noexcept {
        return data.subspan(header_lenght(), total_lenght() - header_lenght());
    }

    std::span<uint8_t> self_packet() const noexcept {
        return data;
    }

private:
    std::span<uint8_t> data;
};

#endif // NETCAP_IPV4_PACKET_VIEW_INCUDED
