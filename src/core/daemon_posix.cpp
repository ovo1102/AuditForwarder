// AuditForwarder - POSIX service / daemon install helper.

#include "auditforwarder/logger.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef AF_PLATFORM_LINUX
#  define AF_SYSTEMD_UNIT "auditforwarder.service"
#endif

namespace af::platform {

int install_systemd(const std::string& data_dir, const std::string& config_path) {
    std::string unit = "/etc/systemd/system/" + std::string(AF_SYSTEMD_UNIT);
    std::string exe  = "/usr/local/bin/auditforwarderd";
    // Discover real path of the running executable
    char buf[4096] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = 0; exe = buf; }

    std::ofstream f(unit);
    if (!f) {
        std::fprintf(stderr, "cannot write %s: %s\n", unit.c_str(), strerror(errno));
        return 1;
    }
    f << "[Unit]\n"
      << "Description=AuditForwarder Security Audit Agent\n"
      << "After=network-online.target\n"
      << "Wants=network-online.target\n"
      << "\n"
      << "[Service]\n"
      << "Type=simple\n"
      << "ExecStart=" << exe << " -c " << config_path << " -d " << data_dir << "\n"
      << "Restart=on-failure\n"
      << "RestartSec=5\n"
      << "LimitNOFILE=65536\n"
      << "CapabilityBoundingSet=CAP_AUDIT_READ CAP_DAC_READ_SEARCH CAP_SYS_PTRACE\n"
      << "AmbientCapabilities=CAP_AUDIT_READ CAP_DAC_READ_SEARCH\n"
      << "NoNewPrivileges=false\n"
      << "ProtectSystem=full\n"
      << "ProtectHome=true\n"
      << "PrivateTmp=true\n"
      << "\n"
      << "[Install]\n"
      << "WantedBy=multi-user.target\n";
    f.close();
    ::chmod(unit.c_str(), 0644);

    int rc = std::system("systemctl daemon-reload");
    if (rc != 0) std::fprintf(stderr, "systemctl daemon-reload returned %d\n", rc);
    rc = std::system("systemctl enable " AF_SYSTEMD_UNIT);
    if (rc != 0) std::fprintf(stderr, "systemctl enable returned %d\n", rc);
    rc = std::system("systemctl start " AF_SYSTEMD_UNIT);
    if (rc != 0) std::fprintf(stderr, "systemctl start returned %d\n", rc);

    std::printf("AuditForwarder installed and started.\n");
    return 0;
}

int uninstall_systemd() {
    std::system("systemctl stop " AF_SYSTEMD_UNIT);
    std::system("systemctl disable " AF_SYSTEMD_UNIT);
    std::string unit = "/etc/systemd/system/" + std::string(AF_SYSTEMD_UNIT);
    if (::unlink(unit.c_str()) != 0 && errno != ENOENT) {
        std::fprintf(stderr, "unlink %s: %s\n", unit.c_str(), strerror(errno));
    }
    std::system("systemctl daemon-reload");
    std::printf("AuditForwarder uninstalled.\n");
    return 0;
}

}  // namespace af::platform

extern "C" int install_service(const std::string& data_dir, const std::string& config_path) {
#ifdef AF_PLATFORM_LINUX
    return af::platform::install_systemd(data_dir, config_path);
#else
    (void)data_dir; (void)config_path;
    std::fprintf(stderr, "install: only supported on Linux in this build\n");
    return 1;
#endif
}

extern "C" int uninstall_service() {
#ifdef AF_PLATFORM_LINUX
    return af::platform::uninstall_systemd();
#else
    std::fprintf(stderr, "uninstall: only supported on Linux in this build\n");
    return 1;
#endif
}
