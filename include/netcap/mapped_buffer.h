#if !defined(NETCAP_MAPPED_BUFFER_INCLUDED)
#define NETCAP_MAPPED_BUFFER_INCLUDED

#include <netcap/byte.h>
#include <memory>
#include <sys/mman.h>

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

#endif // NETCAP_MAPPED_BUFFER_INCLUDED
