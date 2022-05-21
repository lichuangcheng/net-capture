#ifndef NETCAP_TCP_PACKET_VIEW
#define NETCAP_TCP_PACKET_VIEW

#include <span>
#include <netcap/exception.h>
#include <netcap/addr_ipv4.h>
#include <netcap/byte.h>

class TcpPacketView {
public:
    enum { 
        HEADER_LENGTH_MIN = 20
    };
    
    enum Flags : uint8_t {
        CWR = 128,      // Congestion Window Reduce 拥塞窗口减少标志
        ECE = 64,       // ECN Echo 用来在 TCP 三次握手时表明一个 TCP 端是具备 ECN 功能的
        URG = 32,       // Urgent 表示本报文段中发送的数据是否包含紧急数据
        ACK = 16,       // 表示前面的确认号字段是否有效. ACK=1 时表示有效
        PSH = 8,        // Push 告诉对方收到该报文段后是否立即把数据推送给上层
        RST = 4,        // 表示是否重置连接
        SYN = 2,        // 在建立连接时使用
        FIN = 1,        // 标记数据是否发送完毕
    };

    TcpPacketView(std::span<uint8_t> data) : d(data) {
        if (d.size() < HEADER_LENGTH_MIN)
            throw std::invalid_argument("invalid TCP packet");
    }

    uint16_t sender_port() const noexcept {
        return as_host<uint16_t>(&d[0]);
    }

    uint16_t target_port() const noexcept {
        return as_host<uint16_t>(&d[2]);
    }

    // Sequence Number
    uint32_t seq_num() const noexcept {
        return as_host<uint32_t>(&d[4]);
    }
    
    // Acknowledgment Number，ACK Number
    uint32_t ack_num() const noexcept {
        return as_host<uint32_t>(&d[8]);
    }

    // TCP 头部长度, 也叫数据偏移 Offset
    uint8_t header_len() const noexcept {
        return ((d[12] >> 4) & 0xf) * 4;
    }

    // 保留字段，全为0
    uint8_t reserved() const noexcept {
        return d[12] & 0xf;
    }

    // 标志位
    uint8_t flags() const noexcept {
        return d[13];
    }

    // 窗口大小
    uint16_t window_size() const noexcept {
        return as_host<uint16_t>(&d[14]);
    }

    // 校验和 对首部和数据两部分执行 CRC 算法，检验报文是否损坏
    uint16_t checksum() const noexcept {
        return as_host<uint16_t>(&d[16]);
    }

    // 紧急指针
    uint16_t urgent_pointer() const noexcept {
        return as_host<uint16_t>(&d[18]);
    }

    // TCP负载数据
    std::span<uint8_t> playload() const noexcept {
        return d.subspan(header_len());
    }

private:
    std::span<uint8_t> d;
};

#endif // NETCAP_TCP_PACKET_VIEW
