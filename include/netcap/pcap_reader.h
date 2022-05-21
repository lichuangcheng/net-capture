#if !defined(NETCAP_PCAP_READER_INCLUDED)
#define NETCAP_PCAP_READER_INCLUDED

#include <netcap/byte.h>

#include <vector>
#include <span>
#include <cstdint>

#include <netinet/in.h>
#include <arpa/inet.h>

struct PcapHeader {
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    uint32_t this_zone;
    uint32_t sig_figs;
    uint32_t snap_len;
    uint32_t link_type;

    void byteswap(bool swap) {
        major = swap ? ntohs(major) : major;
        minor = swap ? ntohs(minor) : minor;
        this_zone = swap ? ntohl(this_zone) : this_zone;
        sig_figs = swap ? ntohl(sig_figs) : sig_figs;
        snap_len = swap ? ntohl(snap_len) : snap_len;
        link_type = swap ? ntohl(link_type) : link_type;
    }
};
static_assert(sizeof(PcapHeader) == 24);

struct PacketHeader {
    uint32_t second;
    uint32_t microsecond;
    uint32_t caplen;
    uint32_t len;
};
static_assert(sizeof(PacketHeader) == 16);

struct Packet {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
    byte *data;

    Packet(const PacketHeader &head, byte *d) : data(d) {
        ts_sec = head.second;
        ts_usec = head.microsecond;
        caplen = head.caplen;
        len = head.len;
    }

    void byteswap(bool swap) {
        ts_sec = swap ? ntohl(ts_sec) : ts_sec;
        ts_usec = swap ? ntohl(ts_usec) : ts_usec;
        caplen = swap ? ntohl(caplen) : caplen;
        len = swap ? ntohl(len) : len;
    }
};

class PcapReader {
public:
    PcapReader(std::span<byte> buf) : buffer_(buf) {}
    bool parse() {
        if (buffer_.size() < 24)
            return false;

        bool swap = false;
        if (is_little_endian()) {
            if (std::endian::native == std::endian::big) 
                swap = true;
        } else if (is_big_endian()) {
            if (std::endian::native == std::endian::little)
                swap = true;
        } else {
            return false;
        }

        pcap_header_ = *reinterpret_cast<PcapHeader *>(buffer_.data());
        pcap_header_.byteswap(swap);
        packet_list_.reserve(1024);
        size_t pos = 24;
        while (pos + 16 < buffer_.size()) {
            auto head = *reinterpret_cast<PacketHeader *>(buffer_.data() + pos);
            byte *data = buffer_.data() + pos + 16;

            Packet packet(head, data);
            packet.byteswap(swap);
            packet_list_.push_back(packet);

            pos += 16;
            pos += packet.caplen;
        }
        return true;
    }

    const std::vector<Packet> &packet_list() const {
        return packet_list_;
    }

    size_t packet_size() const {
        return packet_list_.size();
    }

    bool is_little_endian() const {
        uint32_t magic = *reinterpret_cast<const uint32_t *>(&buffer_[0]);
        return (magic == 0XA1B2C3D4 || magic == 0XA1B23C4D);
    }

    bool is_big_endian() const {
        uint32_t magic = *reinterpret_cast<const uint32_t *>(&buffer_[0]);
        return magic == 0XD4C3B2A1;
    }

    PcapHeader &pacp_header() {
        return pcap_header_;
    }
    
private:
    std::span<byte> buffer_;
    PcapHeader pcap_header_;
    std::vector<Packet> packet_list_;
};

#endif // NETCAP_PCAP_READER_INCLUDED
