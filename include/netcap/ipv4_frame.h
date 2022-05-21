#if !defined(NETCAP_IPV4_FRAME_INCLUDED)
#define NETCAP_IPV4_FRAME_INCLUDED

#include <netcap/protocol_type.h>
#include <netcap/addr_ipv4.h>
#include <span>

struct IPv4Frame {
public:
    bool deserialize(std::span<uint8_t> data) {
        // 4 byte
        version         = (data[0] >> 4) & 0xf;
        header_len      = (data[0] & 0xf) * 4;
        service_type    = data[1];
        total_lenght    = ntohs(*(uint16_t *)(&data[2]));
        // 4 bytes
        identification  = ntohs(*(uint16_t *)(&data[4]));
        flags           = (data[6] >> 5) & 0b00000111;
        fragment_offset = ntohs(*(uint16_t *)(&data[6])) & 0x1fff;
        // 4 bytes
        ttl             = data[8];
        protocol        = (ProtocolType)data[9];
        header_checksum = ntohs(*(uint16_t *)(&data[10]));
        // 4 bytes
        s_addr.s_addr   = *(uint32_t *)(&data[12]);
        d_addr.s_addr   = *(uint32_t *)(&data[16]);

        // Options Padding ...

        playload  = data.subspan(header_len, total_lenght - header_len);
        self_data = data;
        return true;
    }

    bool dont_fragment() const noexcept {
        return flags & 0b0000'0010;
    }

    bool more_fragment() const noexcept {
        return flags & 0b0000'0001;
    }

    uint8_t version{0};
    uint8_t header_len{0};
    uint8_t service_type{0};

    uint16_t total_lenght{0};
    uint16_t identification{0};

    uint8_t flags{0};
    uint16_t fragment_offset{0};
    uint8_t ttl{0};
    ProtocolType protocol{0};
    uint16_t header_checksum{0};

    AddrIPv4 s_addr;
    AddrIPv4 d_addr;

    std::span<uint8_t> playload;
    std::span<uint8_t> self_data;
};

#endif // NETCAP_IPV4_FRAME_INCLUDED
