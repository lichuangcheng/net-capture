#if !defined(NETCAP_PRINTLN_INCLUDED)
#define NETCAP_PRINTLN_INCLUDED

#include <fmt/format.h>
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <fmt/ostream.h>
#include <fmt/os.h>

template <typename... T> 
inline void println(fmt::format_string<T...> fmt, T &&...args) {
    fmt::print(fmt, std::forward<T>(args)...);
    fmt::print("\n");
}

#endif // NETCAP_PRINTLN_INCLUDED
