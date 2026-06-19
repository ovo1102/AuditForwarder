#include "auditforwarder/config.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace af {

namespace {
std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    auto e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    return s.substr(b, e - b + 1);
}
std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
}  // namespace

// ---------------- ConfigValue ----------------
ConfigValue::ConfigValue(bool v)                       : type_(Type::Bool),   data_(v) {}
ConfigValue::ConfigValue(int v)                        : type_(Type::Int),    data_(static_cast<long long>(v)) {}
ConfigValue::ConfigValue(long v)                       : type_(Type::Int),    data_(static_cast<long long>(v)) {}
ConfigValue::ConfigValue(long long v)                  : type_(Type::Int),    data_(v) {}
ConfigValue::ConfigValue(unsigned v)                   : type_(Type::Int),    data_(static_cast<long long>(v)) {}
ConfigValue::ConfigValue(unsigned long v)              : type_(Type::Int),    data_(static_cast<long long>(v)) {}
ConfigValue::ConfigValue(unsigned long long v)         : type_(Type::Int),    data_(static_cast<long long>(v)) {}
ConfigValue::ConfigValue(double v)                     : type_(Type::Double), data_(v) {}
ConfigValue::ConfigValue(const char* v)                : type_(Type::String), data_(std::string(v)) {}
ConfigValue::ConfigValue(std::string v)                : type_(Type::String), data_(std::move(v)) {}
ConfigValue::ConfigValue(std::vector<ConfigValue> v)   : type_(Type::List),   data_(std::move(v)) {}
ConfigValue::ConfigValue(std::map<std::string, ConfigValue> v) : type_(Type::Map), data_(std::move(v)) {}

bool ConfigValue::as_bool(bool def) const {
    if (type_ == Type::Bool)  return std::get<bool>(data_);
    if (type_ == Type::Int)   return std::get<long long>(data_) != 0;
    if (type_ == Type::String) {
        auto s = to_lower(std::get<std::string>(data_));
        if (s == "true" || s == "yes" || s == "on" || s == "1") return true;
        if (s == "false" || s == "no" || s == "off" || s == "0") return false;
    }
    return def;
}
long long ConfigValue::as_int(long long def) const {
    if (type_ == Type::Int)    return std::get<long long>(data_);
    if (type_ == Type::Double) return static_cast<long long>(std::get<double>(data_));
    if (type_ == Type::Bool)   return std::get<bool>(data_) ? 1 : 0;
    if (type_ == Type::String) {
        try { return std::stoll(std::get<std::string>(data_)); } catch (...) {}
    }
    return def;
}
double ConfigValue::as_double(double def) const {
    if (type_ == Type::Double) return std::get<double>(data_);
    if (type_ == Type::Int)    return static_cast<double>(std::get<long long>(data_));
    if (type_ == Type::String) {
        try { return std::stod(std::get<std::string>(data_)); } catch (...) {}
    }
    return def;
}
std::string ConfigValue::as_string(const std::string& def) const {
    if (type_ == Type::String) return std::get<std::string>(data_);
    if (type_ == Type::Int)    return std::to_string(std::get<long long>(data_));
    if (type_ == Type::Double) {
        std::ostringstream o; o << std::get<double>(data_); return o.str();
    }
    if (type_ == Type::Bool)   return std::get<bool>(data_) ? "true" : "false";
    return def;
}

const std::vector<ConfigValue>& ConfigValue::as_list() const {
    static const std::vector<ConfigValue> empty;
    if (type_ == Type::List) return std::get<std::vector<ConfigValue>>(data_);
    return empty;
}
const std::map<std::string, ConfigValue>& ConfigValue::as_map() const {
    static const std::map<std::string, ConfigValue> empty;
    if (type_ == Type::Map) return std::get<std::map<std::string, ConfigValue>>(data_);
    return empty;
}

bool ConfigValue::has(const std::string& key) const {
    if (type_ != Type::Map) return false;
    return std::get<std::map<std::string, ConfigValue>>(data_).count(key) > 0;
}
const ConfigValue& ConfigValue::at(const std::string& key) const {
    static const ConfigValue null;
    if (type_ != Type::Map) return null;
    const auto& m = std::get<std::map<std::string, ConfigValue>>(data_);
    auto it = m.find(key);
    return it == m.end() ? null : it->second;
}
const ConfigValue& ConfigValue::operator[](const std::string& key) const { return at(key); }

const ConfigValue& ConfigValue::at_index(std::size_t i) const {
    static const ConfigValue null;
    if (type_ != Type::List) return null;
    const auto& v = std::get<std::vector<ConfigValue>>(data_);
    if (i >= v.size()) return null;
    return v[i];
}
std::size_t ConfigValue::size() const {
    if (type_ == Type::List) return std::get<std::vector<ConfigValue>>(data_).size();
    if (type_ == Type::Map)   return std::get<std::map<std::string, ConfigValue>>(data_).size();
    return 0;
}

void ConfigValue::set_path(const std::string& path, const ConfigValue& v) {
    if (type_ == Type::Null) {
        type_ = Type::Map;
        data_ = std::map<std::string, ConfigValue>{};
    }
    if (type_ != Type::Map) return;
    auto& m = std::get<std::map<std::string, ConfigValue>>(data_);
    std::string key = path;
    std::size_t dot = path.find('.');
    if (dot != std::string::npos) {
        std::string head = path.substr(0, dot);
        std::string tail = path.substr(dot + 1);
        if (m.find(head) == m.end()) m[head] = ConfigValue();
        m[head].set_path(tail, v);
    } else {
        m[key] = v;
    }
}

void ConfigValue::merge(const ConfigValue& other) {
    if (other.type_ != Type::Map) return;
    if (type_ == Type::Null) { *this = other; return; }
    if (type_ != Type::Map)   return;
    auto& dst = std::get<std::map<std::string, ConfigValue>>(data_);
    for (const auto& [k, v] : other.as_map()) {
        auto it = dst.find(k);
        if (it == dst.end()) dst.emplace(k, v);
        else {
            if (it->second.type_ == Type::Map && v.type_ == Type::Map) it->second.merge(v);
            else it->second = v;
        }
    }
}

std::string ConfigValue::dump_json() const {
    std::ostringstream o;
    switch (type_) {
        case Type::Null:   o << "null"; break;
        case Type::Bool:   o << (std::get<bool>(data_) ? "true" : "false"); break;
        case Type::Int:    o << std::get<long long>(data_); break;
        case Type::Double: o << std::get<double>(data_); break;
        case Type::String: {
            o << '"';
            for (char c : std::get<std::string>(data_)) {
                switch (c) {
                    case '"':  o << "\\\""; break;
                    case '\\': o << "\\\\"; break;
                    case '\b': o << "\\b";  break;
                    case '\f': o << "\\f";  break;
                    case '\n': o << "\\n";  break;
                    case '\r': o << "\\r";  break;
                    case '\t': o << "\\t";  break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20) {
                            char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                            o << buf;
                        } else o << c;
                }
            }
            o << '"'; break;
        }
        case Type::List: {
            o << '[';
            const auto& v = std::get<std::vector<ConfigValue>>(data_);
            for (std::size_t i = 0; i < v.size(); ++i) {
                if (i) o << ',';
                o << v[i].dump_json();
            }
            o << ']'; break;
        }
        case Type::Map: {
            o << '{';
            const auto& m = std::get<std::map<std::string, ConfigValue>>(data_);
            bool first = true;
            for (const auto& [k, v] : m) {
                if (!first) o << ',';
                first = false;
                o << '"' << k << "\":" << v.dump_json();
            }
            o << '}'; break;
        }
    }
    return o.str();
}

// ---------------- Config ----------------
Config& Config::instance() {
    static Config c;
    return c;
}

void Config::clear() { root_ = ConfigValue(); last_path_.clear(); }

bool Config::get_bool(const std::string& p, bool def) const {
    const ConfigValue* cur = &root_;
    std::string path = p;
    std::size_t start = 0;
    while (start < path.size()) {
        auto dot = path.find('.', start);
        std::string k = (dot == std::string::npos) ? path.substr(start) : path.substr(start, dot - start);
        if (k.empty()) { ++start; continue; }
        if (!cur->has(k)) return def;
        cur = &cur->at(k);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return cur->as_bool(def);
}
long long Config::get_int(const std::string& p, long long def) const {
    const ConfigValue* cur = &root_;
    std::string path = p;
    std::size_t start = 0;
    while (start < path.size()) {
        auto dot = path.find('.', start);
        std::string k = (dot == std::string::npos) ? path.substr(start) : path.substr(start, dot - start);
        if (k.empty()) { ++start; continue; }
        if (!cur->has(k)) return def;
        cur = &cur->at(k);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return cur->as_int(def);
}
double Config::get_double(const std::string& p, double def) const {
    const ConfigValue* cur = &root_;
    std::string path = p;
    std::size_t start = 0;
    while (start < path.size()) {
        auto dot = path.find('.', start);
        std::string k = (dot == std::string::npos) ? path.substr(start) : path.substr(start, dot - start);
        if (k.empty()) { ++start; continue; }
        if (!cur->has(k)) return def;
        cur = &cur->at(k);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return cur->as_double(def);
}
std::string Config::get_string(const std::string& p, const std::string& def) const {
    const ConfigValue* cur = &root_;
    std::string path = p;
    std::size_t start = 0;
    while (start < path.size()) {
        auto dot = path.find('.', start);
        std::string k = (dot == std::string::npos) ? path.substr(start) : path.substr(start, dot - start);
        if (k.empty()) { ++start; continue; }
        if (!cur->has(k)) return def;
        cur = &cur->at(k);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return cur->as_string(def);
}

// ---------------- 简易 YAML/JSON 解析器 ----------------

// 尝试检测格式并解析。公开接口，其他翻译单元（如 rule_engine）可通过头文件声明使用。
Result<void> parse_minimal(const std::string& content, const std::string& format, ConfigValue& out) {
    auto fmt = to_lower(format);
    if (fmt.empty()) {
        if (!content.empty() && (content[0] == '{' || content[0] == '[')) fmt = "json";
        else fmt = "yaml";
    }
    if (fmt == "json") return parse_minimal_json(content, out);
    if (fmt == "yaml" || fmt == "yml") return parse_minimal_yaml(content, out);
    return Result<void>(Error(Error::Code::InvalidArgument, "unsupported config format"));
}

// We split parser implementations into separate translation units to keep this file small.
Result<void> Config::load_from_string(const std::string& content, const std::string& format) {
    ConfigValue v;
    auto r = parse_minimal(content, format, v);
    if (r.is_err()) return r;
    root_ = std::move(v);
    return Result<void>::ok();
}

Result<void> Config::load_from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
        return Result<void>(Error(Error::Code::NotFound, "cannot open: " + path));
    std::ostringstream ss; ss << in.rdbuf();
    last_path_ = path;
    
    // 提取文件扩展名用于格式检测
    std::string ext;
    auto dot = path.rfind('.');
    if (dot != std::string::npos) {
        ext = path.substr(dot + 1);
    }
    return load_from_string(ss.str(), ext);
}

}  // namespace af
