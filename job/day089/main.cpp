#include <netcap/file.h>
#include <netcap/println.h>
#include <netcap/pcap_reader.h>
#include <netcap/ethernetII_view.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/arp_packet_view.h>
#include <concepts>

template <std::integral T>
bool is_null(std::span<T> sp) {
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

        println("总计{}个数据包", reader.packet_size());
        int i = 0;
        for (auto &packet : reader.packet_list()) {
            i++;
            EthernetIIView ether({packet.data, packet.caplen});
            if (ether.is_arp()) {
                println("Frame: {}", i);
                println("[{:%Y-%m-%d %H:%M:%S}.{}] {} Bytes {:02X} {:02X} {}", 
                        fmt::localtime(packet.ts_sec),
                        packet.ts_usec, 
                        packet.caplen,
                        fmt::join(ether.dmac(), ":"),
                        fmt::join(ether.smac(), ":"),
                        ether.type_string());

                ArpPacketView arp(ether.playload());
                println("[ARP请求] {}({:02X}) 查询 {}({:02X}) 的 MAC 地址",
                        arp.sender_ip().to_string(), fmt::join(arp.sender_mac(), ":"), 
                        arp.target_ip().to_string(), fmt::join(arp.target_mac(), ":")
                );
            }
        } 

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
