#include "auditforwarder/process.h"

#include "auditforwarder/logger.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

#ifdef AF_PLATFORM_UNIX
#  include <dirent.h>
#  include <pwd.h>
#  include <signal.h>
#  include <sys/sysinfo.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#ifdef AF_PLATFORM_LINUX
#  include <sys/utsname.h>
#endif

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#  include <lmcons.h>
#  include <psapi.h>
#  include <tlhelp32.h>
#  include <winver.h>
#  pragma comment(lib, "version.lib")
#endif

namespace af::proc {

u32 current_pid() {
#ifdef AF_PLATFORM_WINDOWS
    return ::GetCurrentProcessId();
#else
    return static_cast<u32>(::getpid());
#endif
}

std::string current_username() {
#ifdef AF_PLATFORM_WINDOWS
    char buf[UNLEN + 1];
    DWORD n = UNLEN + 1;
    if (::GetUserNameA(buf, &n)) return std::string(buf, n - 1);
    return "";
#else
    if (char* l = std::getenv("USER"); l && *l) return l;
    if (struct passwd* pw = ::getpwuid(::getuid()); pw && pw->pw_name) return pw->pw_name;
    return "";
#endif
}

std::string hostname() {
#ifdef AF_PLATFORM_WINDOWS
    char buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = sizeof(buf);
    if (::GetComputerNameA(buf, &n)) return std::string(buf, n);
    return "";
#else
    char buf[256];
    if (::gethostname(buf, sizeof(buf)) == 0) return buf;
    return "";
#endif
}

std::string os_version() {
#ifdef AF_PLATFORM_WINDOWS
    OSVERSIONINFOA vi{sizeof(vi)};
    if (::GetVersionExA(&vi)) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "Windows %lu.%lu (build %lu)",
                      vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        return buf;
    }
    return "Windows";
#elif defined(AF_PLATFORM_LINUX)
    std::ifstream f("/etc/os-release");
    std::string line, name = "Linux", ver;
    if (f) {
        while (std::getline(f, line)) {
            if (line.rfind("PRETTY_NAME=", 0) == 0) {
                auto v = line.substr(12);
                if (!v.empty() && v.front() == '"') v.erase(0, 1);
                if (!v.empty() && v.back() == '"') v.pop_back();
                return v;
            }
        }
    }
    return "Linux";
#else
    return "Unix";
#endif
}

std::string kernel_version() {
#ifdef AF_PLATFORM_LINUX
    struct utsname n;
    if (::uname(&n) == 0) return std::string(n.sysname) + " " + n.release;
    return "Linux";
#elif defined(AF_PLATFORM_WINDOWS)
    OSVERSIONINFOA vi{sizeof(vi)};
    if (::GetVersionExA(&vi)) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "%lu.%lu.%lu",
                      vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        return buf;
    }
    return "";
#else
    return "";
#endif
}

bool is_elevated() {
#ifdef AF_PLATFORM_WINDOWS
    BOOL is_admin = FALSE;
    HANDLE h = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    if (::AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        ::CheckTokenMembership(h, admin_group, &is_admin);
        ::FreeSid(admin_group);
    }
    return is_admin != FALSE;
#elif defined(AF_PLATFORM_UNIX)
    return ::getuid() == 0;
#else
    return false;
#endif
}

Result<void> enable_privilege(const std::string& name) {
#ifdef AF_PLATFORM_WINDOWS
    HANDLE h_token;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h_token))
        return Result<void>(Error::Code::PermissionDenied, "OpenProcessToken");
    LUID luid;
    if (!::LookupPrivilegeValueA(nullptr, name.c_str(), &luid)) {
        ::CloseHandle(h_token);
        return Result<void>(Error::Code::NotFound, "LookupPrivilegeValue");
    }
    TOKEN_PRIVILEGES tp{1, {luid, SE_PRIVILEGE_ENABLED}};
    if (!::AdjustTokenPrivileges(h_token, FALSE, &tp, 0, nullptr, nullptr)) {
        ::CloseHandle(h_token);
        return Result<void>(Error::Code::PermissionDenied, "AdjustTokenPrivileges");
    }
    ::CloseHandle(h_token);
    return Result<void>::ok();
#else
    (void)name;
    return Result<void>::ok();
#endif
}

Result<std::vector<ProcessInfo>> list_processes() {
    std::vector<ProcessInfo> out;
#ifdef AF_PLATFORM_LINUX
    DIR* d = ::opendir("/proc");
    if (!d) return Result<std::vector<ProcessInfo>>(Error::Code::IoError, "open /proc");
    while (struct dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        ProcessInfo pi;
        try { pi.pid = static_cast<u32>(std::stoul(e->d_name)); } catch (...) { continue; }
        std::string base = std::string("/proc/") + e->d_name;
        std::ifstream stat(base + "/stat");
        if (stat) {
            std::string buf; std::getline(stat, buf);
            auto rpar = buf.rfind(')');
            auto lpar = buf.find('(');
            if (lpar != std::string::npos && rpar != std::string::npos) {
                pi.name = buf.substr(lpar + 1, rpar - lpar - 1);
            }
        }
        std::ifstream cmd(base + "/cmdline");
        if (cmd) {
            std::string b, full;
            while (std::getline(cmd, b, '\0')) {
                if (!full.empty()) full.push_back(' ');
                full += b;
            }
            pi.cmdline = full;
        }
        std::ifstream s(base + "/status");
        if (s) {
            std::string l;
            while (std::getline(s, l)) {
                if (l.rfind("PPid:", 0) == 0) {
                    pi.ppid = static_cast<u32>(std::strtoul(l.c_str() + 5, nullptr, 10));
                }
            }
        }
        std::ifstream exel(base + "/exe");
        if (exel) {
            std::string l; std::getline(exel, l);
            char resolved[PATH_MAX];
            ssize_t n = ::readlink((base + "/exe").c_str(), resolved, sizeof(resolved) - 1);
            if (n > 0) { resolved[n] = '\0'; pi.exe = resolved; }
        }
        out.push_back(std::move(pi));
    }
    ::closedir(d);
    return out;
#elif defined(AF_PLATFORM_WINDOWS)
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return Result<std::vector<ProcessInfo>>(Error::Code::IoError, "snapshot");
    PROCESSENTRY32 pe{sizeof(pe)};
    if (::Process32First(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.pid     = pe.th32ProcessID;
            pi.ppid    = pe.th32ParentProcessID;
            pi.name    = pe.szExeFile;
            // exe 路径：查询
            HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                char buf[MAX_PATH];
                DWORD n = MAX_PATH;
                if (::QueryFullProcessImageNameA(h, 0, buf, &n)) pi.exe = std::string(buf, n);
                ::CloseHandle(h);
            }
            out.push_back(std::move(pi));
        } while (::Process32Next(snap, &pe));
    }
    ::CloseHandle(snap);
    return out;
#else
    return out;
#endif
}

Result<ProcessInfo> get_process(u32 pid) {
#ifdef AF_PLATFORM_LINUX
    std::string base = "/proc/" + std::to_string(pid);
    if (!::access(base.c_str(), F_OK)) {
        ProcessInfo pi;
        pi.pid = pid;
        std::ifstream stat(base + "/stat");
        if (stat) {
            std::string buf; std::getline(stat, buf);
            auto lpar = buf.find('(');
            auto rpar = buf.rfind(')');
            if (lpar != std::string::npos && rpar != std::string::npos)
                pi.name = buf.substr(lpar + 1, rpar - lpar - 1);
        }
        return pi;
    }
    return Result<ProcessInfo>(Error::Code::NotFound, "process not found");
#elif defined(AF_PLATFORM_WINDOWS)
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return Result<ProcessInfo>(Error::Code::NotFound, "process not found");
    ProcessInfo pi; pi.pid = pid;
    char buf[MAX_PATH]; DWORD n = MAX_PATH;
    if (::QueryFullProcessImageNameA(h, 0, buf, &n)) pi.exe = std::string(buf, n);
    pi.name = pi.exe.empty() ? "" : pi.exe.substr(pi.exe.find_last_of("/\\") + 1);
    ::CloseHandle(h);
    return pi;
#else
    (void)pid;
    return Result<ProcessInfo>(Error::Code::NotSupported, "not implemented");
#endif
}

Result<void> terminate(u32 pid, int sig) {
#ifdef AF_PLATFORM_LINUX
    if (::kill(static_cast<pid_t>(pid), sig) == 0) return Result<void>::ok();
    return Result<void>(Error::Code::PermissionDenied, "kill failed");
#elif defined(AF_PLATFORM_WINDOWS)
    HANDLE h = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return Result<void>(Error::Code::PermissionDenied, "open failed");
    if (!::TerminateProcess(h, static_cast<UINT>(sig))) {
        ::CloseHandle(h);
        return Result<void>(Error::Code::PermissionDenied, "terminate failed");
    }
    ::CloseHandle(h);
    return Result<void>::ok();
#else
    (void)pid; (void)sig;
    return Result<void>(Error::Code::NotSupported, "not implemented");
#endif
}

Result<u32> spawn(const std::vector<std::string>& args,
                  const std::map<std::string, std::string>& env,
                  const std::string& cwd) {
    if (args.empty()) return Result<u32>(Error::Code::InvalidArgument, "empty args");
#ifdef AF_PLATFORM_UNIX
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    std::vector<std::string> env_strs;
    env_strs.reserve(env.size());
    for (auto& [k, v] : env) env_strs.push_back(k + "=" + v);
    std::vector<char*> envp;
    envp.reserve(env_strs.size() + 1);
    for (auto& s : env_strs) envp.push_back(const_cast<char*>(s.c_str()));
    envp.push_back(nullptr);
    pid_t pid = ::fork();
    if (pid < 0) return Result<u32>(Error::Code::IoError, "fork failed");
    if (pid == 0) {
        if (!cwd.empty()) ::chdir(cwd.c_str());
        if (!envp.empty()) ::execve(argv[0], argv.data(), envp.data());
        else              ::execv (argv[0], argv.data());
        ::_exit(127);
    }
    return static_cast<u32>(pid);
#else
    (void)env; (void)cwd;
    STARTUPINFOA si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    std::string cmd;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i) cmd.push_back(' ');
        if (args[i].find(' ') != std::string::npos) cmd.push_back('"');
        cmd += args[i];
        if (args[i].find(' ') != std::string::npos) cmd.push_back('"');
    }
    if (!::CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                          nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) {
        return Result<u32>(Error::Code::IoError, "CreateProcess failed");
    }
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return static_cast<u32>(pi.dwProcessId);
#endif
}

}  // namespace af::proc
