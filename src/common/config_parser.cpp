#include "auditforwarder/config.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <stack>

namespace af {

// ============================================================================
// Minimal JSON parser
// ============================================================================
namespace {

struct JsonCursor {
    const std::string& s;
    std::size_t i;
};

void skip_ws(JsonCursor& c) {
    while (c.i < c.s.size()) {
        char ch = c.s[c.i];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') ++c.i;
        else break;
    }
}

bool consume(JsonCursor& c, char ch) {
    skip_ws(c);
    if (c.i < c.s.size() && c.s[c.i] == ch) { ++c.i; return true; }
    return false;
}

bool peek(JsonCursor& c, char& ch) {
    skip_ws(c);
    if (c.i < c.s.size()) { ch = c.s[c.i]; return true; }
    return false;
}

Result<ConfigValue> parse_json_value(JsonCursor& c);

Result<ConfigValue> parse_json_string(JsonCursor& c) {
    skip_ws(c);
    if (c.i >= c.s.size() || c.s[c.i] != '"')
        return Result<ConfigValue>(Error(Error::Code::Parse, "expected string"));
    ++c.i;
    std::string out;
    while (c.i < c.s.size() && c.s[c.i] != '"') {
        char ch = c.s[c.i++];
        if (ch == '\\' && c.i < c.s.size()) {
            char esc = c.s[c.i++];
            switch (esc) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    if (c.i + 4 > c.s.size())
                        return Result<ConfigValue>(Error(Error::Code::Parse, "bad unicode"));
                    unsigned cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = c.s[c.i++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                        else return Result<ConfigValue>(Error(Error::Code::Parse, "bad unicode"));
                    }
                    if (cp < 0x80) out.push_back(static_cast<char>(cp));
                    else if (cp < 0x800) {
                        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    }
                    break;
                }
                default: out.push_back(esc);
            }
        } else out.push_back(ch);
    }
    if (c.i >= c.s.size())
        return Result<ConfigValue>(Error(Error::Code::Parse, "unterminated string"));
    ++c.i; // consume closing "
    return ConfigValue(std::move(out));
}

Result<ConfigValue> parse_json_number(JsonCursor& c) {
    skip_ws(c);
    std::size_t start = c.i;
    if (c.i < c.s.size() && (c.s[c.i] == '-' || c.s[c.i] == '+')) ++c.i;
    while (c.i < c.s.size() && (std::isdigit(static_cast<unsigned char>(c.s[c.i])) ||
           c.s[c.i] == '.' || c.s[c.i] == 'e' || c.s[c.i] == 'E' || c.s[c.i] == '-' || c.s[c.i] == '+'))
        ++c.i;
    std::string num = c.s.substr(start, c.i - start);
    if (num.empty()) return Result<ConfigValue>(Error(Error::Code::Parse, "bad number"));
    if (num.find('.') != std::string::npos || num.find('e') != std::string::npos ||
        num.find('E') != std::string::npos) {
        try { return ConfigValue(std::stod(num)); }
        catch (...) { return Result<ConfigValue>(Error(Error::Code::Parse, "bad number")); }
    }
    try { return ConfigValue(static_cast<long long>(std::stoll(num))); }
    catch (...) { return Result<ConfigValue>(Error(Error::Code::Parse, "bad number")); }
}

Result<ConfigValue> parse_json_literal(JsonCursor& c, const std::string& lit, ConfigValue v) {
    skip_ws(c);
    if (c.i + lit.size() > c.s.size())
        return Result<ConfigValue>(Error(Error::Code::Parse, "bad literal"));
    if (c.s.compare(c.i, lit.size(), lit) != 0)
        return Result<ConfigValue>(Error(Error::Code::Parse, "bad literal"));
    c.i += lit.size();
    return std::move(v);
}

Result<ConfigValue> parse_json_array(JsonCursor& c) {
    ++c.i; // '['
    std::vector<ConfigValue> arr;
    char ch;
    if (peek(c, ch) && ch == ']') { ++c.i; return ConfigValue(std::move(arr)); }
    while (true) {
        auto v = parse_json_value(c);
        if (v.is_err()) return v;
        arr.push_back(std::move(v).value());
        if (!consume(c, ',')) break;
    }
    if (!consume(c, ']'))
        return Result<ConfigValue>(Error(Error::Code::Parse, "expected ']'"));
    return ConfigValue(std::move(arr));
}

Result<ConfigValue> parse_json_object(JsonCursor& c) {
    ++c.i; // '{'
    std::map<std::string, ConfigValue> obj;
    char ch;
    if (peek(c, ch) && ch == '}') { ++c.i; return ConfigValue(std::move(obj)); }
    while (true) {
        auto k = parse_json_string(c);
        if (k.is_err()) return Result<ConfigValue>(Error(Error::Code::Parse, "expected key string"));
        if (!consume(c, ':'))
            return Result<ConfigValue>(Error(Error::Code::Parse, "expected ':'"));
        auto v = parse_json_value(c);
        if (v.is_err()) return v;
        obj.emplace(std::move(k).value().as_string(), std::move(v).value());
        if (!consume(c, ',')) break;
    }
    if (!consume(c, '}'))
        return Result<ConfigValue>(Error(Error::Code::Parse, "expected '}'"));
    return ConfigValue(std::move(obj));
}

Result<ConfigValue> parse_json_value(JsonCursor& c) {
    skip_ws(c);
    if (c.i >= c.s.size()) return Result<ConfigValue>(Error(Error::Code::Parse, "unexpected eof"));
    char ch = c.s[c.i];
    if (ch == '"') return parse_json_string(c);
    if (ch == '{') return parse_json_object(c);
    if (ch == '[') return parse_json_array(c);
    if (ch == 't') return parse_json_literal(c, "true",  ConfigValue(true));
    if (ch == 'f') return parse_json_literal(c, "false", ConfigValue(false));
    if (ch == 'n') return parse_json_literal(c, "null",  ConfigValue());
    return parse_json_number(c);
}

}  // namespace

Result<void> parse_minimal_json(const std::string& content, ConfigValue& out) {
    JsonCursor c{content, 0};
    auto r = parse_json_value(c);
    if (r.is_err()) return Result<void>(r.error());
    out = std::move(r).value();
    return Result<void>::ok();
}

// ============================================================================
// Minimal YAML parser (subset: maps, sequences, scalars, block style only)
// ============================================================================
namespace {

struct YamlLine {
    int indent;
    std::string content;
};

std::vector<YamlLine> split_lines(const std::string& s) {
    std::vector<YamlLine> r;
    std::istringstream is(s);
    std::string l;
    while (std::getline(is, l)) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        int indent = 0;
        while (indent < static_cast<int>(l.size()) && l[indent] == ' ') ++indent;
        r.push_back({indent, l.substr(indent)});
    }
    return r;
}

Result<ConfigValue> parse_yaml_block(const std::vector<YamlLine>& lines, std::size_t& idx, int base_indent);

std::string unquote(const std::string& s) {
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
                          (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

ConfigValue parse_scalar(const std::string& s) {
    if (s.empty() || s == "~" || s == "null" || s == "Null" || s == "NULL") return ConfigValue();
    if (s == "true" || s == "True" || s == "yes" || s == "on")  return ConfigValue(true);
    if (s == "false" || s == "False" || s == "no" || s == "off") return ConfigValue(false);
    auto t = s;
    bool numeric = !t.empty();
    if (t.front() == '-' || t.front() == '+') t.erase(0, 1);
    bool has_dot = t.find('.') != std::string::npos;
    bool all_digit = !t.empty();
    for (char c : t) {
        if (!std::isdigit(static_cast<unsigned char>(c))) { all_digit = false; break; }
    }
    if (numeric && all_digit) {
        try {
            if (has_dot) return ConfigValue(std::stod(s));
            return ConfigValue(static_cast<long long>(std::stoll(s)));
        } catch (...) {}
    }
    return ConfigValue(unquote(s));
}

bool is_list_item(const std::string& c) {
    return c.size() >= 2 && c[0] == '-' && (c[1] == ' ' || c[1] == '\t');
}

Result<ConfigValue> parse_yaml_map(const std::vector<YamlLine>& lines, std::size_t& idx, int base_indent) {
    std::map<std::string, ConfigValue> obj;
    while (idx < lines.size() && lines[idx].indent >= base_indent) {
        if (lines[idx].indent != base_indent) break;
        const auto& content = lines[idx].content;
        if (content.empty() || content[0] == '#') { ++idx; continue; }
        if (is_list_item(content)) break;

        auto colon = content.find(':');
        if (colon == std::string::npos)
            return Result<ConfigValue>(Error(Error::Code::Parse, "expected key: " + content));

        std::string key = content.substr(0, colon);
        // trim key
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        std::string rest;
        if (colon + 1 < content.size()) {
            rest = content.substr(colon + 1);
            while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.erase(0, 1);
        }
        ++idx;

        if (rest.empty()) {
            if (idx < lines.size() && lines[idx].indent > base_indent) {
                if (is_list_item(lines[idx].content) && lines[idx].indent == base_indent + 2) {
                    // List of maps/mixed
                    std::vector<ConfigValue> arr;
                    while (idx < lines.size() && lines[idx].indent == base_indent + 2 && is_list_item(lines[idx].content)) {
                        std::size_t saved = idx;
                        ++idx;
                        // After "- ", there may be a same-line key:value or a child block
                        auto sub = lines[saved].content.substr(2);
                        while (!sub.empty() && (sub.front() == ' ' || sub.front() == '\t')) sub.erase(0, 1);
                        if (sub.empty()) {
                            // Sub-block at base_indent + 4
                            if (idx < lines.size() && lines[idx].indent > base_indent + 2) {
                                auto inner = parse_yaml_block(lines, idx, lines[idx].indent);
                                if (inner.is_err()) return inner;
                                arr.push_back(std::move(inner).value());
                            } else {
                                arr.push_back(ConfigValue());
                            }
                        } else {
                            // Inline sub key: value, build a single-key map and merge subsequent lines
                            auto sub_colon = sub.find(':');
                            if (sub_colon != std::string::npos) {
                                std::string kk = sub.substr(0, sub_colon);
                                while (!kk.empty() && (kk.back() == ' ' || kk.back() == '\t')) kk.pop_back();
                                std::string vv = (sub_colon + 1 < sub.size()) ? sub.substr(sub_colon + 1) : "";
                                while (!vv.empty() && (vv.front() == ' ' || vv.front() == '\t')) vv.erase(0, 1);
                                std::map<std::string, ConfigValue> m;
                                if (!vv.empty()) m.emplace(kk, parse_scalar(vv));
                                else if (idx < lines.size() && lines[idx].indent > base_indent + 2) {
                                    auto inner = parse_yaml_block(lines, idx, lines[idx].indent);
                                    if (inner.is_err()) return inner;
                                    m.emplace(kk, std::move(inner).value());
                                } else m.emplace(kk, ConfigValue());
                                arr.push_back(ConfigValue(std::move(m)));
                            } else {
                                arr.push_back(parse_scalar(sub));
                            }
                        }
                    }
                    obj.emplace(key, ConfigValue(std::move(arr)));
                } else {
                    auto sub = parse_yaml_block(lines, idx, lines[idx].indent);
                    if (sub.is_err()) return sub;
                    obj.emplace(key, std::move(sub).value());
                }
            } else {
                obj.emplace(key, ConfigValue());
            }
        } else {
            obj.emplace(key, parse_scalar(rest));
        }
    }
    return ConfigValue(std::move(obj));
}

Result<ConfigValue> parse_yaml_block(const std::vector<YamlLine>& lines, std::size_t& idx, int base_indent) {
    // Decide whether this is a list or a map
    if (idx < lines.size() && is_list_item(lines[idx].content) && lines[idx].indent == base_indent) {
        std::vector<ConfigValue> arr;
        while (idx < lines.size() && lines[idx].indent == base_indent && is_list_item(lines[idx].content)) {
            std::size_t saved = idx;
            ++idx;
            auto sub = lines[saved].content.substr(2);
            while (!sub.empty() && (sub.front() == ' ' || sub.front() == '\t')) sub.erase(0, 1);
            if (sub.empty()) {
                if (idx < lines.size() && lines[idx].indent > base_indent) {
                    auto inner = parse_yaml_block(lines, idx, lines[idx].indent);
                    if (inner.is_err()) return inner;
                    arr.push_back(std::move(inner).value());
                } else arr.push_back(ConfigValue());
            } else {
                auto sub_colon = sub.find(':');
                if (sub_colon != std::string::npos) {
                    std::string kk = sub.substr(0, sub_colon);
                    while (!kk.empty() && (kk.back() == ' ' || kk.back() == '\t')) kk.pop_back();
                    std::string vv = (sub_colon + 1 < sub.size()) ? sub.substr(sub_colon + 1) : "";
                    while (!vv.empty() && (vv.front() == ' ' || vv.front() == '\t')) vv.erase(0, 1);
                    std::map<std::string, ConfigValue> m;
                    if (!vv.empty()) m.emplace(kk, parse_scalar(vv));
                    else if (idx < lines.size() && lines[idx].indent > base_indent) {
                        auto inner = parse_yaml_block(lines, idx, lines[idx].indent);
                        if (inner.is_err()) return inner;
                        m.emplace(kk, std::move(inner).value());
                    } else m.emplace(kk, ConfigValue());
                    arr.push_back(ConfigValue(std::move(m)));
                } else {
                    arr.push_back(parse_scalar(sub));
                }
            }
        }
        return ConfigValue(std::move(arr));
    }
    return parse_yaml_map(lines, idx, base_indent);
}

}  // namespace

Result<void> parse_minimal_yaml(const std::string& content, ConfigValue& out) {
    auto lines = split_lines(content);
    std::size_t idx = 0;
    if (lines.empty()) { out = ConfigValue(); return Result<void>::ok(); }
    int base = lines[0].indent;
    auto r = parse_yaml_block(lines, idx, base);
    if (r.is_err()) return Result<void>(r.error());
    out = std::move(r).value();
    return Result<void>::ok();
}

}  // namespace af
