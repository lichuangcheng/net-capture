#include <netcap/file.h>
#include <netcap/println.h>
#include <netcap/pcap_reader.h>
#include <netcap/ethernetII_view.h>
#include <netcap/ipv4_packet_view.h>
#include <netcap/tcp_packet_view.h>

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

        auto &list = reader.packet_list();
        println("packet size: {}", list.size());
        for (size_t i = 0; i < list.size(); ++i) {
            auto &content = list[i];
            EthernetIIView ether({content.data, content.caplen});
            if (!ether.is_ipv4()) continue;

            IPv4PacketView ipv4(ether.playload());
            if (ipv4.protocol() != ProtocolType::TCP) continue;

            println("Frame {}", i + 1);
            TcpPacketView tcp(ipv4.playload());
            println("[{}]->[{}] seq_num: {}, ack_num: {}, header_len={}, window_size={}, checksum=0x{:02x}", 
            tcp.sender_port(), tcp.target_port(), tcp.seq_num(), tcp.ack_num(), tcp.header_len(), tcp.window_size(), tcp.checksum());
        }

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
