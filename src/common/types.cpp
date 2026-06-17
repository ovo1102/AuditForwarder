#include "auditforwarder/types.h"

namespace af {

const char* to_string(Severity s) noexcept {
    switch (s) {
        case Severity::Debug:     return "debug";
        case Severity::Info:      return "info";
        case Severity::Notice:    return "notice";
        case Severity::Warning:   return "warning";
        case Severity::Error:     return "error";
        case Severity::Critical:  return "critical";
        case Severity::Alert:     return "alert";
        case Severity::Emergency: return "emergency";
    }
    return "unknown";
}

Severity severity_from_string(const std::string& s) noexcept {
    if (s == "debug")     return Severity::Debug;
    if (s == "info")      return Severity::Info;
    if (s == "notice")    return Severity::Notice;
    if (s == "warning")   return Severity::Warning;
    if (s == "error")     return Severity::Error;
    if (s == "critical")  return Severity::Critical;
    if (s == "alert")     return Severity::Alert;
    if (s == "emergency") return Severity::Emergency;
    return Severity::Info;
}

}  // namespace af
