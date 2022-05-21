#if !defined(NETCAP_FILE_INCLUDED)
#define NETCAP_FILE_INCLUDED

#include <netcap/mapped_buffer.h>
#include <netcap/exception.h>

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

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

#endif // NETCAP_FILE_INCLUDED

