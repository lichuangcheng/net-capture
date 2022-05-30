#include <netcap/arp_packet_view.h>
#include <netcap/dns_view.h>
#include <netcap/ethernetII_view.h>
#include <netcap/file.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/pcap_view.h>
#include <netcap/println.h>
#include <netcap/tcp_packet_view.h>
#include <netcap/udp_packet_view.h>

#include <chrono>
#include <concepts>
#include <map>
#include <set>

template <std::integral T>
bool is_zero(std::span<T> sp) {
    return std::all_of(sp.begin(), sp.end(), [](T i) { return i == 0; });
}

class ArpOut {
public:
    ArpOut(const char *name) : out(fmt::output_file(name)) {}
    virtual void append(const PcapPacketView &packet, const ArpPacketView &arp) {
        out.print("[{:%Y-%m-%d %H:%M:%S}] {} Bytes {:02X} {:02X} ", 
                  fmt::localtime(packet.ts_sec()), packet.caplen(), 
                  fmt::join(arp.sender_mac(), "-"), fmt::join(arp.target_mac(), "-"));
        if (is_zero(arp.target_mac())) {
            out.print("查询{}的MAC地址\n", arp.target_ip().to_string());
        } else {
            out.print("响应{}的MAC地址\n", arp.sender_ip().to_string());
        }
    }
private:
    fmt::ostream out;
};

class Ipv4Out {
public:
    Ipv4Out(const char *name) : out(fmt::output_file(name)) {}

    void append(const PcapPacketView &packet, const EthernetIIView &ether, const IPv4PacketView &ipv4) {
        format_prefix(packet, ether);
        out.print("{} {}\n", ipv4.sender_ip().to_string(), ipv4.target_ip().to_string());
    }

protected:
    void format_prefix(const PcapPacketView &packet, const EthernetIIView &ether) {
        out.print("[{:%Y-%m-%d %H:%M:%S}] {} Bytes {:02X} {:02X} ", 
                  fmt::localtime(packet.ts_sec()), packet.caplen(), 
                  fmt::join(ether.smac(), "-"), fmt::join(ether.dmac(), "-"));
    }

protected:
    fmt::ostream out;
};

class UdpOut : public Ipv4Out {
public:
    UdpOut(const char *name) : Ipv4Out(name) {}

    // [时间] 数据包长度 源MAC地址 目的MAC地址 网络层协议名 源IP地址 目的IP地址 源端口 目的端口
    // [2022-01-12 15:00:01] 548 Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A IPv4 192.168.1.100 192.168.1.4 32006 67
    void append(const PcapPacketView &packet, const EthernetIIView &ether, const IPv4PacketView &ipv4,
                const UdpPacketView &udp) {
        format_prefix(packet, ether);
        out.print("IPv4 {} {} {} {}\n", ipv4.sender_ip().to_string(), ipv4.target_ip().to_string(), udp.sender_port(),
                  udp.target_port());
    }
};

class DNSOut : public UdpOut {
public:
    DNSOut(const char *name) : UdpOut(name) {}

    // > [时间] 数据包长度 源MAC地址 目的MAC地址 网络层协议名 源IP地址 目的IP地址 源端口 目的端口 DNS包类型 请求内容/响应内容
    // >
    // > 示例：[2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A IPv4 192.168.1.100 192.168.1.4 32006 67 DNS请求 查询域名www.baidu.com的地址
    // >
    // > 示例：[2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A IPv4 192.168.1.100 192.168.1.4 32006 67 DNS响应 域名www.baidu.com的地址是220.195.20.10
    void append(const PcapPacketView &packet, const EthernetIIView &ether, const IPv4PacketView &ipv4,
                const UdpPacketView &udp, const DNSView &dns) {
        format_prefix(packet, ether);
        out.print("IPv4 {} {} {} {} ", ipv4.sender_ip().to_string(), ipv4.target_ip().to_string(), udp.sender_port(),
                  udp.target_port());

        auto &name = dns.query_list()[0].name();
        if (dns.is_query()) {
            out.print("DNS请求 查询域名{}的地址\n", name);
        }
        else {
            std::vector<std::string> addrs;
            for (auto &resp : dns.response_list()) {
                if (resp.is_ipv4()) {
                    auto addr = AddrIPv4{as<uint32_t>(resp.resource_data().data())}.to_string();
                    addrs.push_back(std::move(addr));
                }
            }
            out.print("DNS响应 域名{}的地址是{}\n", name, fmt::join(addrs, ","));
        }
    }
};

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        println("Usage: {} <.pcap>", argv[0]);
        return 1;
    }
    try {
        ArpOut arp_out("arp.txt");
        Ipv4Out ip_out("ip.txt");
        UdpOut udp_out("udp.txt");
        DNSOut dns_out("dns.txt");

        File f(argv[1], O_RDONLY);
        auto buffer = f.map_readonly();

        // 开启计时
        auto start = std::chrono::steady_clock::now();
        PcapView pcap_view(buffer);
        PcapPacketView packet;
        while (pcap_view.next(packet)) {
            EthernetIIView ether(packet.data());
            if (ether.is_arp()) {
                arp_out.append(packet, ArpPacketView(ether.playload()));
                continue;
            }

            if (!ether.is_ipv4())
                continue;
            IPv4PacketView ipv4(ether.playload());
            ip_out.append(packet, ether, ipv4);

            if (ipv4.protocol() != ProtocolType::UDP)
                continue;
            
            UdpPacketView udp(ipv4.playload());
            udp_out.append(packet, ether, ipv4, udp);
            if (udp.target_port() != 53 && udp.sender_port() != 53)
                continue;
            DNSView dns(udp.playload());
            dns_out.append(packet, ether, ipv4, udp, dns);
        }
        // 结束计时
        auto end = std::chrono::steady_clock::now();
        println("解析耗时: {}ms", std::chrono::duration<double, std::milli>(end - start).count());

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
