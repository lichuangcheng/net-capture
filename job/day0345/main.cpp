#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <netinet/in.h>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <bit>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <type_traits>
#include <unistd.h>

#include <fmt/format.h>
#include <fmt/chrono.h>
#include <vector>
#include <span>

template <typename... T>
inline void println(std::string_view fmt, T&&... args) {
    fmt::print(fmt, std::forward<T>(args)...);
    fmt::print("\n");
}

template <typename T>
inline void println(const T& args) {
    fmt::print("{}\n", args);
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

using byte = std::byte;

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

    int fd() const noexcept {
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
    uint32_t second;
    uint32_t microsecond;
    uint32_t caplen;
    uint32_t len;
    byte *data;

    Packet(const PacketHeader &head, byte *d) : data(d) {
        second = head.second;
        microsecond = head.microsecond;
        caplen = head.caplen;
        len = head.len;
    }

    void byteswap(bool swap) {
        second = swap ? ntohl(second) : second;
        microsecond = swap ? ntohl(microsecond) : microsecond;
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
            println("[{:%Y-%m-%d %H:%M:%S}.{}] {} Bytes", fmt::localtime(packet.second), packet.microsecond, packet.caplen);
        } 

    } catch (const std::exception &e) {
        println("exception: {}", e.what());
    }
    return 0;
}
