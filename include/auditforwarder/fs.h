#pragma once
// AuditForwarder - 跨平台文件系统/路径工具。

#include "auditforwarder/types.h"
#include <string>
#include <vector>

namespace af::fs {

std::string normalize(const std::string& path);
std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string extension(const std::string& path);
std::string join(const std::string& a, const std::string& b);
std::string join(const std::vector<std::string>& parts);
std::string absolute(const std::string& path);
bool        is_absolute(const std::string& path);

bool        exists(const std::string& path);
bool        is_directory(const std::string& path);
bool        is_regular(const std::string& path);
bool        is_symlink(const std::string& path) noexcept;
std::uint64_t file_size(const std::string& path);
Result<std::vector<std::string>> list_directory(const std::string& path);

Result<void> create_directory(const std::string& path, bool recursive = true);
Result<void> create_directories(const std::string& path);
Result<void> remove(const std::string& path, bool recursive = false);
Result<void> rename(const std::string& from, const std::string& to);

std::string read_symlink(const std::string& path);

std::string temp_directory();
std::string current_working_directory();

std::string home_directory();
std::string executable_path();

}  // namespace af::fs
