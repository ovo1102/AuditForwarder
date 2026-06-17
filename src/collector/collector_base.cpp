#include "auditforwarder/collector_base.h"

#include <algorithm>
#include <cctype>
#include <regex>

namespace af::collector {

// Simple glob matcher (no fnmatch dependency). Supports '*' and '?' only.
static bool glob_match(const std::string& pat, const std::string& s) {
    std::size_t pi = 0, si = 0;
    std::size_t star_pi = std::string::npos, star_si = 0;
    while (si < s.size()) {
        if (pi < pat.size() && (pat[pi] == '?' || std::tolower(static_cast<unsigned char>(pat[pi])) ==
                                                   std::tolower(static_cast<unsigned char>(s[si])))) {
            ++pi; ++si;
        } else if (pi < pat.size() && pat[pi] == '*') {
            star_pi = pi++; star_si = si;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            si = ++star_si;
        } else return false;
    }
    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

void PathFilter::include(const std::vector<std::string>& patterns) {
    for (auto& p : patterns) includes_.push_back(p);
}
void PathFilter::exclude(const std::vector<std::string>& patterns) {
    for (auto& p : patterns) excludes_.push_back(p);
}

bool PathFilter::allows(const std::string& path) const {
    auto match_any = [](const std::vector<std::string>& pats, const std::string& s) {
        for (const auto& p : pats) {
            if (glob_match(p, s)) return true;
            try { if (std::regex_search(s, std::regex(p))) return true; } catch (...) {}
        }
        return false;
    };
    if (!includes_.empty() && !match_any(includes_, path)) return false;
    if (!excludes_.empty() && match_any(excludes_, path)) return false;
    return true;
}

}  // namespace af::collector
