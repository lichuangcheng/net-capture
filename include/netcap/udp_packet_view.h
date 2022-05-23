#ifndef NETCAP_UDP_PACKET_VIEW
#define NETCAP_UDP_PACKET_VIEW

#include <span>
#include <netcap/exception.h>
#include <netcap/byte.h>

class UdpPacketView {
public:
    enum { 
        HEADER_LENGTH = 8 
    };

    UdpPacketView(std::span<uint8_t> data) : d(data) {
        if (d.size() < HEADER_LENGTH)
            throw std::invalid_argument("invalid UDP packet");
    }

    // 源端口
    uint16_t sender_port() const noexcept {
        return as_host<uint16_t>(&d[0]);
    }

    // 目的端口
    uint16_t target_port() const noexcept {
        return as_host<uint16_t>(&d[2]);
    }

    // UDP 数据报长度，包含报文头和数据长度, 所以最小为 8
    uint16_t lenght() const noexcept {
        return as_host<uint16_t>(&d[4]);
    }

    // 校验和
    uint16_t checksum() const noexcept {
        return as_host<uint16_t>(&d[6]);
    }

    // UDP负载数据
    std::span<uint8_t> playload() const noexcept {
        return d.subspan(HEADER_LENGTH, lenght() - HEADER_LENGTH);
    }

private:
    std::span<uint8_t> d;
};

#endif // NETCAP_UDP_PACKET_VIEW
