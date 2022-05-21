#if !defined(NETCAP_EXCEPTION_INCLUDED)
#define NETCAP_EXCEPTION_INCLUDED

#include <stdexcept>
#include <string>
#include <string.h>

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

#endif // NETCAP_EXCEPTION_INCLUDED
