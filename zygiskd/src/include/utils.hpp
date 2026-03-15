#pragma once

#include <string>

namespace utils {

// --- SELinux and Android Property Utilities ---

// Sets the SELinux context for socket creation for the current thread.
bool set_socket_create_context(const char* context);

// Gets the current SELinux context of the process.
std::string get_current_attr();

// Retrieves an Android system property value.
std::string get_property(const char* name);

// --- Unix Socket and IPC Extensions ---

// Sends a datagram packet to a Unix socket path.
bool unix_datagram_sendto(const char* path, const void* buf, size_t len);

// Checks if a Unix socket is still alive and connected using `poll`.
bool is_socket_alive(int fd);

} // namespace utils
