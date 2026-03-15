#include "magisk.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <mutex>

#include "constants.hpp"
#include "logging.hpp"

namespace magisk {

static const char* MAGISK_OFFICIAL_PKG = "com.topjohnwu.magisk";
static const std::pair<const char*, const char*> MAGISK_THIRD_PARTIES[] = {
    {"alpha", "io.github.vvb2060.magisk"},
    {"kitsune", "io.github.huskydg.magisk"},
};

static std::once_flag variant_flag;
static std::string magisk_variant_pkg;

static std::optional<std::string> run_command(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) return std::nullopt;

    std::string result;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        result += buf;
    }
    if (fp) pclose(fp);

    // trim
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
        result.pop_back();
    }
    if (result.empty()) return std::nullopt;
    return result;
}

static void detect_variant() {
    std::call_once(variant_flag, []() {
        if (auto version_str = run_command("magisk -v 2>/dev/null")) {
            for (const auto& pair : MAGISK_THIRD_PARTIES) {
                if (version_str.value().find(pair.first) != std::string::npos) {
                    LOGI("Detected Magisk variant: %s", pair.first);
                    magisk_variant_pkg = pair.second;
                    return;
                }
            }
        }
        LOGI("Detected official Magisk variant.");
        magisk_variant_pkg = MAGISK_OFFICIAL_PKG;
    });
}

std::optional<Version> detect_version() {
    auto version_str = run_command("magisk -V 2>/dev/null");
    if (!version_str) return std::nullopt;

    int version = std::stoi(version_str.value());
    detect_variant();

    if (version >= MIN_MAGISK_VERSION) {
        return Version::Supported;
    } else {
        return Version::TooOld;
    }
}

bool uid_granted_root(int32_t uid) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "magisk --sqlite 'SELECT 1 FROM policies WHERE uid=%d AND policy=2 LIMIT 1' 2>/dev/null", uid);
    if (auto output = run_command(cmd)) {
        return true;
    }
    return false;
}

bool uid_should_umount(int32_t uid) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pm list packages --uid %d 2>/dev/null", uid);
    auto list = run_command(cmd);
    if (!list) return false;

    // Output is typically "package:com.example.app uid:10000"
    std::string list_str = list.value();
    size_t pos = list_str.find("package:");
    if (pos == std::string::npos) return false;

    pos += 8; // "package:"
    size_t space_pos = list_str.find(' ', pos);
    std::string pkg_name = list_str.substr(pos, space_pos == std::string::npos ? std::string::npos : space_pos - pos);

    if (pkg_name.empty()) return false;

    char sqlite_cmd[512];
    snprintf(sqlite_cmd, sizeof(sqlite_cmd), "magisk --sqlite 'SELECT 1 FROM denylist WHERE package_name=\"%s\" LIMIT 1' 2>/dev/null", pkg_name.c_str());
    if (auto output = run_command(sqlite_cmd)) {
        return true;
    }
    return false;
}

bool uid_is_manager(int32_t uid) {
    if (auto output = run_command("magisk --sqlite 'SELECT value FROM strings WHERE key=\"requester\" LIMIT 1' 2>/dev/null")) {
        std::string val = output.value();
        if (val.find("value=") == 0) {
            std::string manager_pkg = val.substr(6);
            char path[256];
            snprintf(path, sizeof(path), "/data/user_de/0/%s", manager_pkg.c_str());
            struct stat st;
            if (stat(path, &st) == 0) {
                return st.st_uid == static_cast<uid_t>(uid);
            }
        }
    }

    if (!magisk_variant_pkg.empty()) {
        char path[256];
        snprintf(path, sizeof(path), "/data/user_de/0/%s", magisk_variant_pkg.c_str());
        struct stat st;
        if (stat(path, &st) == 0) {
            return st.st_uid == static_cast<uid_t>(uid);
        }
    }

    LOGD("Could not determine Magisk manager UID.");
    return false;
}

} // namespace magisk
