#pragma once
// AuditForwarder - 配置加载器 (YAML，JSON 作为备选)。

#include "auditforwarder/types.h"
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace af {

class ConfigValue;

// 为实现翻译单元暴露的解析函数。
Result<void> parse_minimal_json(const std::string& content, ConfigValue& out);
Result<void> parse_minimal_yaml(const std::string& content, ConfigValue& out);
Result<void> parse_minimal(const std::string& content, const std::string& format, ConfigValue& out);

// 轻量级动态值，避免对 yaml-cpp/nlohmann_json 的硬依赖。
class ConfigValue {
public:
    enum class Type { Null, Bool, Int, Double, String, List, Map };

    ConfigValue() = default;
    ConfigValue(bool v);
    ConfigValue(int v);
    ConfigValue(long v);
    ConfigValue(long long v);
    ConfigValue(unsigned v);
    ConfigValue(unsigned long v);
    ConfigValue(unsigned long long v);
    ConfigValue(double v);
    ConfigValue(const char* v);
    ConfigValue(std::string v);
    ConfigValue(std::vector<ConfigValue> v);
    ConfigValue(std::map<std::string, ConfigValue> v);

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }

    bool        as_bool(bool def = false) const;
    long long   as_int(long long def = 0) const;
    double      as_double(double def = 0.0) const;
    std::string as_string(const std::string& def = {}) const;

    const std::vector<ConfigValue>&       as_list() const;
    const std::map<std::string, ConfigValue>& as_map() const;

    bool has(const std::string& key) const;
    const ConfigValue& at(const std::string& key) const;
    const ConfigValue& operator[](const std::string& key) const;

    const ConfigValue& at_index(std::size_t i) const;
    std::size_t        size() const;

    // 使用点分隔路径 "a.b.c" 设置嵌套键。按需创建映射。
    void set_path(const std::string& path, const ConfigValue& v);

    // 将另一个映射合并到当前映射（其他映射覆盖当前）。
    void merge(const ConfigValue& other);

    std::string dump_json() const;

private:
    Type                                              type_ { Type::Null };
    std::variant<bool, long long, double, std::string,
                 std::vector<ConfigValue>,
                 std::map<std::string, ConfigValue>> data_;
};

class Config {
public:
    static Config& instance();
    Result<void> load_from_file(const std::string& path);
    Result<void> load_from_string(const std::string& content, const std::string& format);
    void         clear();

    const ConfigValue& root() const { return root_; }
    ConfigValue&       root()       { return root_; }

    // 使用点分隔路径的便捷获取方法
    bool        get_bool(const std::string& path, bool def = false) const;
    long long   get_int(const std::string& path, long long def = 0) const;
    double      get_double(const std::string& path, double def = 0.0) const;
    std::string get_string(const std::string& path, const std::string& def = {}) const;

    std::string last_loaded_path() const { return last_path_; }
    std::string dump_json() const { return root_.dump_json(); }

private:
    ConfigValue root_;
    std::string last_path_;
};

}  // namespace af
