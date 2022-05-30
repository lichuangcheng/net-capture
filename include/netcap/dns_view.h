#ifndef NETCAP_DNS_VIEW
#define NETCAP_DNS_VIEW

#include <span>
#include <netcap/exception.h>
#include <netcap/byte.h>
#include <netcap/addr_ipv4.h>
#include <string>
#include <netcap/println.h>

class ResourceViewBase {
public:
    // 域名字符串
    const std::string &name() const noexcept {
        return name_;
    }

    // [name]字段结束位置，包含结束符的0; 若为压缩存储，则固定等于2
    uint16_t name_end_pos() const noexcept {
        return name_end_;
    }

    // 类型
    uint16_t type() const noexcept {
        return as_host<uint16_t>(&d[name_end_]);
    }

    bool is_ipv4() const noexcept {
        return type() == 0x01;
    }

    bool is_cname() const noexcept {
        return type() == 0x05;
    }

    // 类
    uint16_t Class() const noexcept {
        return as_host<uint16_t>(&d[name_end_ + 2]);
    }

    // 该条资源记录的总长度
    virtual uint16_t total_len() const noexcept {
        return name_end_ + 2 + 2;
    }

    std::string to_string() const {
        return fmt::format("[name: {} type: {} class: {}]", name(), type(), Class());
    }

    friend std::ostream &operator<<(std::ostream &os, const ResourceViewBase &res) {
        return os << res.to_string();
    }

    ResourceViewBase(std::span<uint8_t> dns, size_t offset) : dns{dns}, d{dns.subspan(offset)}, offset_(offset) {
        parse_name(offset);
    }

protected:
    bool parse_name(uint16_t offset) {
        if (d.size() < 2)
            return false;
        name_.reserve(64);
        name_end_ = 0;
        bool found_ptr = false;
        auto pos = offset;
        uint8_t len = dns[pos];
        while (len != 0) {
            if (is_pointer(len)) {
                pos = as_host<uint16_t>(&dns[pos]) & 0x3fff;
                len = dns[pos];
                found_ptr = true;
                continue;
            }
            if (pos + 1u + len > dns.size())
                return false;
            if (!found_ptr)
                name_end_ += (len + 1);
            name_.append((char *)&dns[pos + 1], len);
            pos += (len + 1);
            len = dns[pos];
            if (len != 0)
                name_.append(".");
        }
        if (found_ptr)
            name_end_ += 2;
        else 
            name_end_ += 1;
        return true;
    }

    bool is_pointer(uint8_t value) const noexcept {
        return ((value >> 6) & 0x03) == 0x03;
    }

    std::string name_;
    uint16_t name_end_{0};
    std::span<uint8_t> dns;
    std::span<uint8_t> d;
    size_t offset_{0};
};

class QueryResourceView : public ResourceViewBase {
public:
    using ResourceViewBase::ResourceViewBase;
};

class ResponseResourceView : public ResourceViewBase {
public:
    using ResourceViewBase::ResourceViewBase;

    uint32_t ttl() const noexcept {
        return as_host<uint32_t>(&d[name_end_ + 4]);
    }

    uint16_t resource_data_len() const noexcept {
        return as_host<uint16_t>(&d[name_end_ + 8]);
    }

    std::span<uint8_t> resource_data() const noexcept {
        return d.subspan(name_end_ + 10, resource_data_len());
    }

    // [name] + [type] + [class] + [ttl] + [resource data len] + [resource_data]
    uint16_t total_len() const noexcept override {
        return name_end_ + 2 + 2 + 4 + 2 + resource_data_len();
    }

    AddrIPv4 ipv4_addr() const noexcept {
        if (is_ipv4())
            return AddrIPv4{as<uint32_t>(resource_data().data())};
        // TODO throw exception
        return {};
    }

    std::string cname() const noexcept {
        return parse_cname(offset_ + name_end_ + 10);
    }

private:
    std::string parse_cname(uint16_t offset) const {
        std::string cname;
        cname.reserve(64);
        auto pos = offset;
        uint8_t len = dns[pos];
        while (len != 0) {
            if (is_pointer(len)) {
                pos = as_host<uint16_t>(&dns[pos]) & 0x3fff;
                len = dns[pos];
                continue;
            }
            cname.append((char *)&dns[pos + 1], len);
            pos += (len + 1);
            len = dns[pos];
            if (len != 0)
                cname.append(".");
        }
        return cname;
    }
};

class DNSView {
public:
    enum {
        HEADER_LENGTH = 12, // 报文头长度
        PORT = 52           // 协议使用的端口
    };

    DNSView(std::span<uint8_t> data) : d(data) {
        if (d.size() < HEADER_LENGTH)
            throw std::invalid_argument("invalid UDP packet");

        // 解析问题资源
        query_list_.reserve(questions());
        uint16_t pos = HEADER_LENGTH;
        for (uint16_t i = 0; i < questions(); i++) {
            QueryResourceView query(d, pos);
            pos += query.total_len();
            query_list_.push_back(std::move(query));
        }

        if (is_query())
            return;

        // 解析答案资源报文
        auto answer_cnt = this->answer_rrs();
        resp_list_.reserve(answer_cnt);
        for (uint16_t i = 0; i < answer_cnt; i++) {
            ResponseResourceView resp(d, pos);
            pos += resp.total_len();
            resp_list_.push_back(std::move(resp));
        }
    }

    // 事务ID
    uint16_t transaction_id() const noexcept {
        return as_host<uint16_t>(&d[0]);
    }

    // 标志 DNS 报文中的标志字段
    uint16_t flags() const noexcept {
        return as_host<uint16_t>(&d[2]);
    }

    uint8_t QR() const noexcept {
        return (flags() & 0x8000) >> 15;
    }

    // 是否为请求报文
    bool is_query() const noexcept {
        return !is_response();
    }

    // 是否为响应报文
    bool is_response() const noexcept {
        return flags() & 0x8000;
    }

    // 问题计数 DNS 查询请求的数目
    uint16_t questions() const noexcept {
        return as_host<uint16_t>(&d[4]);
    }

    // 回答资源记录数：DNS 响应的数目。
    uint16_t answer_rrs() const noexcept {
        return as_host<uint16_t>(&d[6]);
    }

    // 权威名称服务器计数：权威名称服务器的数目。
    uint16_t authority_rrs() const noexcept {
        return as_host<uint16_t>(&d[8]);
    }

    // 附加资源记录数：额外的记录数目（权威名称服务器对应 IP 地址的数目）
    uint16_t additional_rrs() const noexcept {
        return as_host<uint16_t>(&d[10]);
    }

    // 请求资源列表
    const std::vector<QueryResourceView> &query_list() const {
        return query_list_;
    }

    // 回答资源列表
    const std::vector<ResponseResourceView> &response_list() const {
        return resp_list_;
    }

private:
    std::span<uint8_t> d;
    std::vector<QueryResourceView> query_list_;
    std::vector<ResponseResourceView> resp_list_;
};

#endif // NETCAP_DNS_VIEW
