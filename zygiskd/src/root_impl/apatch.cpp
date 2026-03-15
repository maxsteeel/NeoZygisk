#include "apatch.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <mutex>

#include "constants.hpp"
#include "logging.hpp"

namespace apatch {

struct PackageInfo {
    int32_t uid;
    bool exclude;
    bool allow;
};

static const char* CONFIG_FILE = "/data/adb/ap/package_config";

static std::mutex cache_mutex;
static std::optional<std::pair<time_t, std::vector<PackageInfo>>> config_cache;

std::optional<Version> detect_version() {
    FILE* fp = popen("apd -V", "r");
    if (!fp) return std::nullopt;

    char buf[128] = {0};
    if (fgets(buf, sizeof(buf), fp)) {
        char* token = strtok(buf, " \t\r\n");
        if (token) {
            token = strtok(nullptr, " \t\r\n");
            if (token) {
                int version = atoi(token);
                if (fp) pclose(fp);
                if (version >= MIN_APATCH_VERSION) {
                    return Version::Supported;
                } else {
                    return Version::TooOld;
                }
            }
        }
    }
    if (fp) pclose(fp);
    return std::nullopt;
}

static std::optional<std::vector<PackageInfo>> get_config() {
    struct stat st;
    if (stat(CONFIG_FILE, &st) != 0) {
        return std::nullopt;
    }

    time_t mtime = st.st_mtime;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (config_cache.has_value()) {
            if (config_cache.value().first == mtime) {
                return config_cache.value().second;
            }
        }
    }

    FILE* fp = fopen(CONFIG_FILE, "r");
    if (!fp) return std::nullopt;

    std::vector<PackageInfo> result;
    char line[512];

    // Skip header
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return std::nullopt;
    }

    while (fgets(line, sizeof(line), fp)) {
        int exclude_val, allow_val;
        int32_t uid_val;

        // format: pkg_name,exclude,allow,uid,...
        char pkg_name[256];
        if (sscanf(line, "%255[^,],%d,%d,%d", pkg_name, &exclude_val, &allow_val, &uid_val) >= 4) {
            result.push_back({uid_val, exclude_val == 1, allow_val == 1});
        }
    }
    fclose(fp);

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        config_cache = std::make_pair(mtime, result);
    }

    return result;
}

bool uid_granted_root(int32_t uid) {
    auto config = get_config();
    if (!config.has_value()) return false;
    for (const auto& pkg : config.value()) {
        if (pkg.uid == uid && pkg.allow) return true;
    }
    return false;
}

bool uid_should_umount(int32_t uid) {
    auto config = get_config();
    if (!config.has_value()) return false;
    for (const auto& pkg : config.value()) {
        if (pkg.uid == uid && pkg.exclude) return true;
    }
    return false;
}

bool uid_is_manager(int32_t uid) {
    struct stat st;
    if (stat("/data/user_de/0/me.bmax.apatch", &st) == 0) {
        return st.st_uid == static_cast<uid_t>(uid);
    }
    return false;
}

} // namespace apatch
