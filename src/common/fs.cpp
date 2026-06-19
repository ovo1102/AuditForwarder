#include "auditforwarder/fs.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef AF_PLATFORM_UNIX
#  include <dirent.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <pwd.h>
#  define AF_PATH_MAX PATH_MAX
#else
#  include <direct.h>
#  include <io.h>
#  include <windows.h>
#  define AF_PATH_MAX MAX_PATH
#endif

namespace af::fs {

namespace {
bool both_slashes(char a, char b) {
    return (a == '/' || a == '\\') && (b == '/' || b == '\\');
}
char native_sep() {
#ifdef AF_PLATFORM_WINDOWS
    return '\\';
#else
    return '/';
#endif
}
}  // namespace

std::string normalize(const std::string& path) {
    if (path.empty()) return ".";
    std::string out;
    out.reserve(path.size());
    char prev = 0;
    for (char c : path) {
        char cc = (c == '/' || c == '\\') ? native_sep() : c;
        if (out.empty()) out.push_back(cc);
        else if (both_slashes(out.back(), cc)) { /* skip */ }
        else out.push_back(cc);
        prev = cc;
    }
    while (out.size() > 1 && (out.back() == '/' || out.back() == '\\')) {
#ifdef AF_PLATFORM_WINDOWS
        if (out.size() == 3 && out[1] == ':') break;
#endif
        out.pop_back();
    }
    if (out.empty()) out.push_back(native_sep());
    return out;
}

std::string dirname(const std::string& path) {
    std::string n = normalize(path);
    auto pos = n.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return std::string(1, native_sep());
#ifdef AF_PLATFORM_WINDOWS
    if (pos == 2 && n[1] == ':') {
        n[2] = native_sep();
        n.resize(3);
        return n;
    }
#endif
    return n.substr(0, pos);
}

std::string basename(const std::string& path) {
    std::string n = normalize(path);
    auto pos = n.find_last_of("/\\");
    if (pos == std::string::npos) return n;
    return n.substr(pos + 1);
}

std::string extension(const std::string& path) {
    std::string b = basename(path);
    auto dot = b.find_last_of('.');
    if (dot == std::string::npos || dot == 0) return {};
    return b.substr(dot);
}

std::string join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    char la = a.back();
    bool a_sep = (la == '/' || la == '\\');
    bool b_sep = (b.front() == '/' || b.front() == '\\');
    if (a_sep && b_sep) return a + b.substr(1);
    if (!a_sep && !b_sep) return a + native_sep() + b;
    return a + b;
}

std::string join(const std::vector<std::string>& parts) {
    std::string r;
    for (const auto& p : parts) r = join(r, p);
    return r;
}

std::string absolute(const std::string& path) {
#ifdef AF_PLATFORM_WINDOWS
    char buf[MAX_PATH];
    if (_fullpath(buf, path.c_str(), MAX_PATH)) return std::string(buf);
    return path;
#else
    char buf[PATH_MAX];
    if (realpath(path.c_str(), buf)) return std::string(buf);
    // 回退到手动解析
    if (!path.empty() && path[0] == '/') return normalize(path);
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) return normalize(std::string(cwd) + "/" + path);
    return path;
#endif
}

bool is_absolute(const std::string& path) {
    if (path.empty()) return false;
#ifdef AF_PLATFORM_WINDOWS
    if (path.size() >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':') return true;
    if (path.size() >= 2 && (path[0] == '\\' || path[0] == '/') && (path[1] == '\\' || path[1] == '/')) return true;
    return false;
#else
    return path[0] == '/';
#endif
}

bool exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

bool is_directory(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IFDIR) != 0;
}

bool is_regular(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IFREG) != 0;
}

bool is_symlink(const std::string& path) noexcept {
#ifdef AF_PLATFORM_WINDOWS
    (void)path;
    return false; // Windows 符号链接处理方式不同
#else
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) return false;
    return S_ISLNK(st.st_mode);
#endif
}

std::uint64_t file_size(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return 0;
    return static_cast<std::uint64_t>(st.st_size);
}

Result<std::vector<std::string>> list_directory(const std::string& path) {
    std::vector<std::string> out;
#ifdef AF_PLATFORM_WINDOWS
    WIN32_FIND_DATAA fd;
    std::string pat = join(path, "*");
    HANDLE h = FindFirstFileA(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return Result<std::vector<std::string>>(Error(Error::Code::NotFound, "cannot list: " + path));
    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        out.push_back(join(path, name));
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR* d = ::opendir(path.c_str());
    if (!d) return Result<std::vector<std::string>>(Error(Error::Code::NotFound, "cannot list: " + path));
    while (struct dirent* e = ::readdir(d)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        out.push_back(join(path, name));
    }
    ::closedir(d);
#endif
    return out;
}

Result<void> create_directory(const std::string& path, bool recursive) {
    if (path.empty()) return Result<void>(Error::Code::InvalidArgument, "empty path");
    if (exists(path) && is_directory(path)) return Result<void>::ok();
    if (recursive) {
        auto parent = dirname(path);
        if (!parent.empty() && parent != "." && parent != path) {
            auto r = create_directory(parent, true);
            if (r.is_err() && r.error().code() != Error::Code::AlreadyExists) return r;
        }
    }
#ifdef AF_PLATFORM_WINDOWS
    if (::CreateDirectoryA(path.c_str(), nullptr)) return Result<void>::ok();
    DWORD err = ::GetLastError();
    if (err == ERROR_ALREADY_EXISTS) return Result<void>::ok();
    return Result<void>(Error::Code::IoError, "mkdir failed: " + path);
#else
    if (::mkdir(path.c_str(), 0755) == 0) return Result<void>::ok();
    if (errno == EEXIST) return Result<void>::ok();
    return Result<void>(Error::Code::IoError, std::string("mkdir failed: ") + strerror(errno));
#endif
}

Result<void> create_directories(const std::string& path) { return create_directory(path, true); }

Result<void> remove(const std::string& path, bool recursive) {
    if (!exists(path)) return Result<void>::ok();
#ifdef AF_PLATFORM_WINDOWS
    if (is_directory(path) && recursive) {
        auto lst = list_directory(path);
        if (lst.is_ok()) {
            for (auto& p : lst.value()) {
                auto r = remove(p, true);
                if (r.is_err()) return r;
            }
        }
        if (::RemoveDirectoryA(path.c_str())) return Result<void>::ok();
        return Result<void>(Error::Code::IoError, "rmdir failed: " + path);
    } else {
        if (::DeleteFileA(path.c_str())) return Result<void>::ok();
        return Result<void>(Error::Code::IoError, "delete failed: " + path);
    }
#else
    if (is_directory(path) && !is_symlink(path)) {
        if (recursive) {
            auto lst = list_directory(path);
            if (lst.is_ok()) {
                for (auto& p : lst.value()) {
                    auto r = remove(p, true);
                    if (r.is_err()) return r;
                }
            }
        }
        if (::rmdir(path.c_str()) == 0) return Result<void>::ok();
        return Result<void>(Error::Code::IoError, std::string("rmdir failed: ") + strerror(errno));
    } else {
        if (::unlink(path.c_str()) == 0) return Result<void>::ok();
        return Result<void>(Error::Code::IoError, std::string("unlink failed: ") + strerror(errno));
    }
#endif
}

Result<void> rename(const std::string& from, const std::string& to) {
#ifdef AF_PLATFORM_WINDOWS
    if (::MoveFileExA(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING)) return Result<void>::ok();
    return Result<void>(Error::Code::IoError, "rename failed");
#else
    if (::rename(from.c_str(), to.c_str()) == 0) return Result<void>::ok();
    return Result<void>(Error::Code::IoError, std::string("rename failed: ") + strerror(errno));
#endif
}

std::string read_symlink(const std::string& path) {
#ifdef AF_PLATFORM_WINDOWS
    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return path;
    char buf[MAX_PATH];
    DWORD n = ::GetFinalPathNameByHandleA(h, buf, MAX_PATH, FILE_NAME_NORMALIZED);
    ::CloseHandle(h);
    if (n == 0 || n >= MAX_PATH) return path;
    std::string s(buf);
    if (s.find(R"(\\?\UNC\)") == 0) s = s.substr(8), s = R"(\\)" + s;
    else if (s.find(R"(\\?\)") == 0) s = s.substr(4);
    return s;
#else
    char buf[PATH_MAX];
    ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (n < 0) return path;
    buf[n] = '\0';
    return std::string(buf);
#endif
}

std::string temp_directory() {
#ifdef AF_PLATFORM_WINDOWS
    char buf[MAX_PATH];
    DWORD n = ::GetTempPathA(MAX_PATH, buf);
    if (n == 0 || n >= MAX_PATH) return "C:\\Windows\\Temp";
    return std::string(buf);
#else
    const char* p = std::getenv("TMPDIR");
    if (p && *p) return p;
    return "/tmp";
#endif
}

std::string current_working_directory() {
#ifdef AF_PLATFORM_WINDOWS
    char buf[MAX_PATH];
    if (::GetCurrentDirectoryA(MAX_PATH, buf)) return buf;
    return ".";
#else
    char buf[PATH_MAX];
    if (::getcwd(buf, sizeof(buf))) return buf;
    return ".";
#endif
}

std::string home_directory() {
#ifdef AF_PLATFORM_WINDOWS
    const char* h = std::getenv("USERPROFILE");
    if (h) return h;
    return "C:\\";
#else
    const char* h = std::getenv("HOME");
    if (h && *h) return h;
    struct passwd* pw = ::getpwuid(::getuid());
    if (pw && pw->pw_dir) return pw->pw_dir;
    return "/";
#endif
}

std::string executable_path() {
#ifdef AF_PLATFORM_LINUX
    char buf[PATH_MAX];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; return buf; }
    return "";
#elif defined(AF_PLATFORM_WINDOWS)
    char buf[MAX_PATH];
    DWORD n = ::GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "";
    return std::string(buf, n);
#else
    return "";
#endif
}

}  // namespace af::fs
