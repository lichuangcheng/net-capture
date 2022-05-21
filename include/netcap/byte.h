#if !defined(NETCAP_BEYT_INCLUDED)
#define NETCAP_BEYT_INCLUDED

#include <bit>
#include <stdint.h>
#include <concepts>

using byte = uint8_t;

inline constexpr bool is_little_end = std::endian::native == std::endian::little;
inline constexpr bool is_big_end = std::endian::native == std::endian::big;

uint16_t byteswap(uint16_t x) {
    return ((x & 0xff) << 8) | ((x & 0xff00) >> 8);
}

uint32_t byteswap(uint32_t x) {
    return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | ((x << 24) & 0xff00000u);
}

template <std::integral T>
inline auto to_host(T x) -> T {
    if (is_big_end) return x;
    return byteswap(x);
}

template <std::integral T>
inline auto as(const void *d) -> T {
    return (*reinterpret_cast<const T *>(d));
}

template <std::integral T>
inline auto as_host(const void *d) -> T {
    return to_host(*reinterpret_cast<const T *>(d));
}

#endif // NETCAP_BEYT_INCLUDED
