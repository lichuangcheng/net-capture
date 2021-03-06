#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

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

class MappedBuffer {
public:
    char *data() noexcept {
        return d->data;
    }
    const char *data() const noexcept {
        return d->data;
    }
    char *begin() noexcept {
        return d->data;
    }
    const char *begin() const noexcept {
        return d->data;
    }
    char *end() {
        return d->data + d->len;
    }
    const char *end() const noexcept {
        return d->data + d->len;
    }
    size_t size() const noexcept {
        return d->len;
    }
    char &operator[](size_t idx) noexcept {
        return d->data[idx];
    }
    const char &operator[](size_t idx) const noexcept {
        return d->data[idx];
    }

    MappedBuffer(MappedBuffer &&) = default;
    MappedBuffer &operator=(MappedBuffer &&) = default;

    friend class File;

private:
    MappedBuffer(char *map_addr, size_t map_len, char *data, size_t len) : d{new Data_(map_addr, map_len, data, len)} {}

    struct Data_ {
        char *map_addr;
        size_t map_len;
        char *data;
        size_t len;
        Data_(char *maddr, size_t mlen, char *d, size_t sz) : map_addr(maddr), map_len(mlen), data(d), len(sz) {}
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
        if (offset >= size())
            throw std::invalid_argument("offset is past end of file");

        if (offset + length > size())
            length = size() - offset;

        off_t page_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
        char *map_addr = (char *)::mmap(0, length + offset - page_offset, PROT_READ, MAP_PRIVATE, fd_, page_offset);
        if (map_addr == MAP_FAILED)
            throw IOException("mmap");

        char *data = map_addr + offset - page_offset;
        size_t map_len = length + offset - page_offset;
        return MappedBuffer{map_addr, map_len, data, length};
    }

    ~File() noexcept {
        close();
    }

    File(const File &) = delete;
    File &operator=(const File &) = delete;
};

int main(int argc, char const *argv[]) {
    try {
        auto print_hex = [](const char *d, size_t sz) {
            for (size_t i = 0; i < sz; ++i)
                printf("%02X ", uint8_t(d[i]));
            printf("\n");
        };

        File f("f8cab909-04f5-497a-ac0f-402c62268360.png", O_RDONLY);
        auto buffer = f.map_readonly();

        print_hex(buffer.data(), 64);
        print_hex(buffer.data() + buffer.size() - 64, 64);

    } catch (const std::exception &e) {
        fprintf(stderr, "exception: %s\n", e.what());
    }
    return 0;
}
