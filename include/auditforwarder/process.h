#pragma once
// AuditForwarder - 跨平台进程工具。

#include "auditforwarder/types.h"
#include <map>
#include <string>
#include <vector>

namespace af::proc {

struct ProcessInfo {
    u32     pid        { 0 };
    u32     ppid       { 0 };
    std::string name;
    std::string exe;
    std::string cmdline;
    std::string username;
    u64     start_time { 0 };
};

u32          current_pid();
std::string  current_username();
std::string  hostname();
std::string  os_version();
std::string  kernel_version();

bool         is_elevated();
Result<void> enable_privilege(const std::string& name);

Result<std::vector<ProcessInfo>> list_processes();
Result<ProcessInfo>              get_process(u32 pid);
Result<void>                     terminate(u32 pid, int signal_or_exit_code = 0);

Result<u32>                      spawn(const std::vector<std::string>& args,
                                      const std::map<std::string, std::string>& env = {},
                                      const std::string& cwd = {});

}  // namespace af::proc
