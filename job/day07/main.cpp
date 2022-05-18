#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <bit>
#include <stdexcept>
#include <string.h>
#include <string>
#include <unistd.h>

#include <fmt/format.h>
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <vector>
#include <span>
#include <array>
#include "protocol_type.h"

template <typename... T> 
inline void println(std::string_view fmt, T &&...args) {
    fmt::print(fmt, std::forward<T>(args)...);
    fmt::print("\n");
}

class IOException : public std::exception {
    int code_;
    std::string msg_;

public:
    IOException(const std::string &msg) : code_(errno), msg_(msg) {
        msg_.append(": ");
        msg_.append(strerror(code_));
    }
    IOException(const std::string &msg, const std::string &arg) : IOException(msg + ": " + arg) {}
    int code() const noexcept {
        return code_;
    }
    const char *what() const noexcept {
        return msg_.c_str();
    }
};

using byte = uint8_t;

class MappedBuffer {
public:
    byte *data() noexcept {
        return d->data;
    }
    const byte *data() const noexcept {
        return d->data;
    }
    byte *begin() noexcept {
        return d->data;
    }
    const byte *begin() const noexcept {
        return d->data;
    }
    byte *end() {
        return d->data + d->len;
    }
    const byte *end() const noexcept {
        return d->data + d->len;
    }
    size_t size() const noexcept {
        return d->len;
    }
    byte &operator[](size_t idx) noexcept {
        return d->data[idx];
    }
    const byte &operator[](size_t idx) const noexcept {
        return d->data[idx];
    }

    MappedBuffer(MappedBuffer &&) = default;
    MappedBuffer &operator=(MappedBuffer &&) = default;

    friend class File;

private:
    MappedBuffer(byte *map_addr, size_t map_len, byte *data, size_t len) : d{new Data_(map_addr, map_len, data, len)} {}

    struct Data_ {
        byte *map_addr;
        size_t map_len;
        byte *data;
        size_t len;
        Data_(byte *maddr, size_t mlen, byte *d, size_t sz) : map_addr(maddr), map_len(mlen), data(d), len(sz) {}
        ~Data_() { ::munmap(map_addr, map_len); }
    };
    std::unique_ptr<Data_> d;
};

class File {
    int fd_{-1};
    struct stat st_;

public:
    File(const char *fname, int flags) {
        if ((fd_ = open(fname, flags)) == -1)
            throw IOException("Cannot open file", fname);
        if (fstat(fd_, &st_) != 0)
            throw IOException("fstat");
    }

    void close() noexcept {
        if (fd_ != -1) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int fileno() const noexcept {
        return fd_;
    }

    struct stat &stat() {
        return st_;
    }

    size_t size() const noexcept {
        return st_.st_size;
    }

    MappedBuffer map_readonly() {
        return map_readonly(0, size());
    }

    MappedBuffer map_readonly(off_t offset, size_t length) {
        if (offset >= static_cast<off_t>(size()))
            throw std::invalid_argument("offset is past end of file");

        if (offset + length > size())
            length = size() - offset;

        off_t page_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
        byte *map_addr = (byte *)::mmap(0, length + offset - page_offset, PROT_READ, MAP_PRIVATE, fd_, page_offset);
        if (map_addr == MAP_FAILED)
            throw IOException("mmap");

        byte *data = map_addr + offset - page_offset;
        size_t map_len = length + offset - page_offset;
        return MappedBuffer{map_addr, map_len, data, length};
    }

    ~File() noexcept {
        close();
    }

    File(const File &) = delete;
    File &operator=(const File &) = delete;
};

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
        return buffer_[0] == byte(0xd4) && buffer_[1] == byte{0xc3} && 
               buffer_[2] == byte{0xb2} && buffer_[3] == byte{0xa1};
    }

    bool is_big_endian() const {
        return buffer_[0] == byte(0xa1) && buffer_[1] == byte{0xb2} && 
               buffer_[2] == byte{0xc3} && buffer_[3] == byte{0xd4};
    }

    PcapHeader &pacp_header() {
        return pcap_header_;
    }
    
private:
    std::span<byte> buffer_;
    PcapHeader pcap_header_;
    std::vector<Packet> packet_list_;
};

struct EthernetII {
    constexpr static int ETH_ALEN = 6;
    
    std::span<uint8_t, ETH_ALEN> dmac;
    std::span<uint8_t, ETH_ALEN> smac;
    uint16_t type;
    std::span<uint8_t> playload;

    EthernetII(std::span<uint8_t> packet) 
        : dmac(packet.subspan(0, ETH_ALEN))
        , smac(packet.subspan(ETH_ALEN, ETH_ALEN * 2)) 
        , type(ntohs(*(uint16_t *)(packet.data() + ETH_ALEN * 2)))
        , playload(packet.subspan(ETH_ALEN * 2 + 2)) {}

    const char* type_string() const {
        switch (type)
        {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x0835: return "RARP";
        case 0x86DD: return "IPv6";
        default:     return "";
        }
    }
};

struct AddrIPv4 : in_addr {
    std::string to_string() const {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&s_addr);
        return fmt::format("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    }
};

class IPv4Frame {
public:
    bool deserialize(std::span<uint8_t> data) {
        // 4 byte
        version_         = (data[0] >> 4) & 0xf;
        header_len_      = (data[0] & 0xf) * 4;
        service_type_    = data[1];
        total_len_       = ntohs(*(uint16_t *)(&data[2]));
        // 4 bytes
        identification_  = ntohs(*(uint16_t *)(&data[4]));
        flags_           = (data[6] >> 5) & 0b00000111;
        fragment_offset_ = ntohs(*(uint16_t *)(&data[6])) & 0x1fff;
        // 4 bytes
        ttl_             = data[8];
        protocol_        = (ProtocolType)data[9];
        header_checksum_ = ntohs(*(uint16_t *)(&data[10]));
        // 4 bytes
        s_addr_.s_addr   = *(uint32_t *)(&data[12]);
        d_addr_.s_addr   = *(uint32_t *)(&data[16]);

        // Options Padding ...

        playload_ = data.subspan(header_len_, total_len_ - header_len_);
        return true;
    }

    uint8_t header_lenght() const noexcept {
        return header_len_;
    }

    AddrIPv4 s_addr() const {
        return s_addr_;
    }

    AddrIPv4 d_addr() const {
        return d_addr_;
    }

    uint16_t total_length() const {
        return total_len_;
    }

    uint8_t TTL() const {
        return ttl_;
    }

    ProtocolType protocol() const {
        return protocol_;
    }

    bool dont_fragment() const noexcept {
        return flags_ & 0b0000'0010;
    }

    bool more_fragment() const noexcept {
        return flags_ & 0b0000'0001;
    }

    std::span<uint8_t> playload() const {
        return playload_;
    }

private:
    uint8_t version_{0};
    uint8_t header_len_{0};
    uint8_t service_type_{0};

    uint16_t total_len_{0};
    uint16_t identification_{0};

    uint8_t flags_{0};
    uint16_t fragment_offset_{0};
    uint8_t ttl_{0};
    ProtocolType protocol_{0};
    uint16_t header_checksum_{0};

    AddrIPv4 s_addr_;
    AddrIPv4 d_addr_;

    std::span<uint8_t> playload_;
};

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
        for (auto &packet : reader.packet_list()) {

            EthernetII ether({packet.data, packet.caplen});
            
            fmt::print("[{:%Y-%m-%d %H:%M:%S}.{}] {} Bytes {:02X} {:02X} {}", 
                    fmt::localtime(packet.ts_sec),
                    packet.ts_usec, 
                    packet.caplen,
                    fmt::join(ether.dmac, ":"),
                    fmt::join(ether.smac, ":"),
                    ether.type_string());

            if (ether.type == 0x0800) {
                IPv4Frame ipv4_f;
                ipv4_f.deserialize(ether.playload);
                fmt::print(" s_addr: {}, d_addr: {}, protocol: {}", 
                            ipv4_f.s_addr().to_string(), 
                            ipv4_f.d_addr().to_string(),
                            to_string(ipv4_f.protocol()));
            }
            println("");
        } 

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
