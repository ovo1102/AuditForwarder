// AuditForwarder - Windows service install helper (sc.exe based).

#include "auditforwarder/logger.h"
#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#endif

namespace af::platform {

int install_windows_service(const std::string& data_dir, const std::string& config_path) {
#ifdef AF_PLATFORM_WINDOWS
    char exe[MAX_PATH];
    DWORD n = ::GetModuleFileNameA(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        std::fprintf(stderr, "GetModuleFileName failed\n");
        return 1;
    }
    std::string binpath = std::string(exe, n) + " -c " + config_path + " -d " + data_dir;
    std::string cmd = "sc create AuditForwarder binPath= \"" + binpath + "\" start= auto";
    std::printf("%s\n", cmd.c_str());
    if (std::system(cmd.c_str()) != 0) {
        std::fprintf(stderr, "sc create failed\n");
        return 1;
    }
    std::system("sc start AuditForwarder");
    std::printf("AuditForwarder installed and started.\n");
    return 0;
#else
    (void)data_dir; (void)config_path;
    return 1;
#endif
}

int uninstall_windows_service() {
#ifdef AF_PLATFORM_WINDOWS
    std::system("sc stop AuditForwarder");
    std::system("sc delete AuditForwarder");
    std::printf("AuditForwarder uninstalled.\n");
    return 0;
#else
    return 1;
#endif
}

}  // namespace af::platform

extern "C" int install_service(const std::string& data_dir, const std::string& config_path) {
#ifdef AF_PLATFORM_WINDOWS
    return af::platform::install_windows_service(data_dir, config_path);
#else
    (void)data_dir; (void)config_path;
    std::fprintf(stderr, "install: not implemented for this platform\n");
    return 1;
#endif
}

extern "C" int uninstall_service() {
#ifdef AF_PLATFORM_WINDOWS
    return af::platform::uninstall_windows_service();
#else
    std::fprintf(stderr, "uninstall: not implemented for this platform\n");
    return 1;
#endif
}
