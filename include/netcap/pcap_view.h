#ifndef NETCAP_PCAP_VIEW_INCLUDED
#define NETCAP_PCAP_VIEW_INCLUDED

#include <netcap/byte.h>
#include <netcap/exception.h>
#include <span>

class PcapBase {
protected:
    bool need_swap{false};

    template <std::integral T>
    inline auto read_as(const void *ptr) const -> T {
        if (need_swap)
            return byteswap(as<T>(ptr));
        else
            return as<T>(ptr);
    }
};

class PcapPacketView : public PcapBase {
public:
    enum { 
        HEADER_LENGHT = 16 
    };

    PcapPacketView() = default;

    PcapPacketView(std::span<byte> sp, bool sw) : d(sp) {
        need_swap = sw;
    }

    bool is_damaged() const noexcept {
        return d.size() < HEADER_LENGHT;
    }

    bool empty() const noexcept {
        return d.empty();
    }

    uint32_t ts_sec() const noexcept {
        return read_as<uint32_t>(&d[0]);
    }

    uint32_t ts_usec() const noexcept {
        return read_as<uint32_t>(&d[4]);
    }

    uint32_t caplen() const noexcept {
        return read_as<uint32_t>(&d[8]);
    }

    uint32_t len() const noexcept {
        return read_as<uint32_t>(&d[12]);
    }

    std::span<byte> data() const {
        return d.subspan(HEADER_LENGHT, caplen());
    }

private:
    std::span<byte> d;
};

class PcapView : public PcapBase {
public:
    enum {
        HEADER_LENGHT = 24
    };

    PcapView(std::span<byte> buffer) : d(buffer) {
        if (d.size() < HEADER_LENGHT)
            throw std::invalid_argument("invalid PCAP packet");
        if (pcap_little_endian()) {
            if (is_big_end)
                need_swap = true;
        } else if (pcap_big_endian()) {
            if (is_little_end)
                need_swap = true;
        } else {
            throw std::invalid_argument("invalid pcap file");
        }
    }

    uint32_t magic() const noexcept {
        return read_as<uint32_t>(&d[0]);
    }

    uint16_t major() const noexcept {
        return read_as<uint16_t>(&d[4]);
    }

    uint16_t minor() const noexcept {
        return read_as<uint16_t>(&d[6]);
    }

    uint32_t this_zone() const noexcept {
        return read_as<uint32_t>(&d[8]);
    }

    uint32_t sig_figs() const noexcept {
        return read_as<uint32_t>(&d[12]);
    }

    uint32_t snap_len() const noexcept {
        return read_as<uint32_t>(&d[16]);
    }

    uint32_t link_type() const noexcept {
        return read_as<uint32_t>(&d[20]);
    }

    bool next(PcapPacketView &view)  {
        if (pos + PcapPacketView::HEADER_LENGHT >= d.size())
            return false;
        view = PcapPacketView(d.subspan(pos), need_swap);
        pos += PcapPacketView::HEADER_LENGHT;
        pos += view.caplen();
        return true;
    }

protected:
    bool pcap_little_endian() const noexcept {
        uint32_t magic = as<uint32_t>(&d[0]);
        return (magic == 0XA1B2C3D4 || magic == 0XA1B23C4D);
    }

    bool pcap_big_endian() const noexcept {
        uint32_t magic = as<uint32_t>(&d[0]);
        return magic == 0XD4C3B2A1;
    }
    
private:
    std::span<byte> d;
    size_t pos{HEADER_LENGHT};
};

#endif // NETCAP_PCAP_VIEW_INCLUDED
