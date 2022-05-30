#include <netcap/file.h>
#include <netcap/println.h>
#include <netcap/ethernetII_view.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/pcap_view.h>
#include <netcap/udp_packet_view.h>
#include <netcap/tcp_packet_view.h>

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        println("Usage: {} <.pcap>", argv[0]);
        return 1;
    }
    try {
        File f(argv[1], O_RDONLY);
        auto buffer = f.map_readonly();

        PcapView pcap_view(buffer);
        PcapPacketView packet;
        while (pcap_view.next(packet)) {
            EthernetIIView ether(packet.data());
            if (!ether.is_ipv4())
                continue;
            IPv4PacketView ipv4(ether.playload());
            if (ipv4.protocol() != ProtocolType::UDP)
                continue;

            UdpPacketView udp(ipv4.playload());
            println("[{:%Y-%m-%d %H:%M:%S}] {} Bytes {:02X} {:02X} {}->{} {}->{} {}", 
                    fmt::localtime(packet.ts_sec()), packet.caplen(),             // 数据包时间、长度信息
                    fmt::join(ether.dmac(), ":"), fmt::join(ether.smac(), ":"),   // 目的MAC地址、源MAC地址
                    ipv4.sender_ip().to_string(), ipv4.target_ip().to_string(),   // 源IP地址、目的IP地址
                    udp.sender_port(), udp.target_port(), udp.playload().size()); // 源端口、目的端口、UDP数据长度
        }

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
