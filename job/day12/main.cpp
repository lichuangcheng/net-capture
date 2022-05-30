#include <netcap/file.h>
#include <netcap/println.h>
#include <netcap/ethernetII_view.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/pcap_view.h>
#include <netcap/udp_packet_view.h>
#include <netcap/tcp_packet_view.h>
#include <netcap/dns_view.h>
#include <map>
#include <set>

std::string get_query_names(const DNSView &dns) {
    if (dns.query_list().empty()) 
        return "";
    std::vector<std::string> out;
    out.reserve(dns.query_list().size());
    for (auto &q : dns.query_list()) {
        out.push_back(q.name());
    }
    return fmt::format("{}", fmt::join(out, " "));
}

std::string get_resp_names(const DNSView &dns) {
    std::map<std::string, std::vector<std::string>> name_addr;
    for (auto &resp : dns.response_list()) {
        if (!resp.is_ipv4()) continue;
        auto addr = AddrIPv4{as<uint32_t>(resp.resource_data().data())}.to_string();
        name_addr[resp.name()].push_back(std::move(addr));
    }
    return fmt::format("{}", name_addr);
}

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        println("Usage: {} <.pcap>", argv[0]);
        return 1;
    }
    try {
        File f(argv[1], O_RDONLY);
        auto buffer = f.map_readonly();
        int i = 0;
        std::string_view QR[] = {"查询", "响应"};
        std::map<std::string, std::set<std::string>> domain;
        PcapView pcap_view(buffer);
        PcapPacketView packet;
        while (pcap_view.next(packet)) {
            i++;
            // if (i != 926) continue;
            EthernetIIView ether(packet.data());
            if (!ether.is_ipv4())
                continue;
            IPv4PacketView ipv4(ether.playload());
            if (ipv4.protocol() != ProtocolType::UDP)
                continue;
            
            UdpPacketView udp(ipv4.playload());
            if (udp.target_port() != 53 && udp.sender_port() != 53)
                continue;

            println("Frame: {}", i);
            println("[{:%Y-%m-%d %H:%M:%S}] {} Bytes {:02X} {:02X} {}->{} {}->{} {}", 
                    fmt::localtime(packet.ts_sec()), packet.caplen(),             // 数据包时间、长度信息
                    fmt::join(ether.dmac(), ":"), fmt::join(ether.smac(), ":"),   // 目的MAC地址、源MAC地址
                    ipv4.sender_ip().to_string(), ipv4.target_ip().to_string(),   // 源IP地址、目的IP地址
                    udp.sender_port(), udp.target_port(), udp.playload().size()); // 源端口、目的端口、UDP数据长度
            DNSView dns(udp.playload());
            println("DNS{} {} {}", QR[dns.QR()], get_query_names(dns), get_resp_names(dns));
            if (dns.is_response()) {
                auto &name = dns.query_list()[0].name();
                for (auto &resp : dns.response_list()) {
                    if (resp.is_ipv4()) {
                        auto addr = AddrIPv4{as<uint32_t>(resp.resource_data().data())}.to_string();
                        domain[name].insert(std::move(addr));
                    }
                    if (resp.is_cname()) {
                        // domain[name].insert(std::move(resp.cname()));
                    }
                }
            }
        }
        println("- 域名  IP地址");
        for (auto &[n, addr] : domain)
            println("- {} {}", n, fmt::join(addr, ","));

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
