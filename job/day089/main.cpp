#include <netcap/file.h>
#include <netcap/println.h>
#include <netcap/pcap_reader.h>
#include <netcap/ethernetII_view.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/arp_packet_view.h>

#include <map>
#include <concepts>

template <std::integral T>
bool is_zero(std::span<T> sp) {
    return std::all_of(sp.begin(), sp.end(), [](T i) { return i == 0; });
}

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        println("Usage: {} <.pcap>", argv[0]);
        return 1;
    }
    try {
        File f(argv[1], O_RDONLY);
        auto buffer = f.map_readonly();

        PcapReader reader(buffer);
        if (!reader.parse()) {
            println("invalid pcap file");
            return 1;
        }

        std::map<AddrIPv4, std::span<uint8_t>> arp_map;
        for (auto &packet : reader.packet_list()) {
            EthernetIIView ether({packet.data, packet.caplen});
            if (ether.is_arp()) {
                ArpPacketView arp(ether.playload());
                auto sender_ip = arp.sender_ip().to_string();
                auto target_ip = arp.target_ip().to_string();

                if (is_zero(arp.target_mac())) {
                    println("[ARP请求] {}({:02X}) 查询 {} 的 MAC 地址", 
                            sender_ip, fmt::join(arp.sender_mac(), ":"), target_ip);
                } else {
                    println("[ARP响应] {}({:02X}) 回复 {}({:02X}): {} 的MAC地址在我这里",
                            sender_ip, fmt::join(arp.sender_mac(), ":"),
                            target_ip, fmt::join(arp.target_mac(), ":"), sender_ip);
                }
                arp_map.emplace(arp.sender_ip(), arp.sender_mac());
            }
        }
        println("- IP地址  MAC地址");
        for (auto &[ip, mac] : arp_map) {
            println("- {} {:02X}", ip.to_string(), fmt::join(mac, ":"));
        }

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
