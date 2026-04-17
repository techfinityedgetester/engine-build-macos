#!/usr/bin/env python3

target_path = "engine/src/flutter/runtime/runtime_controller.cc"

with open(target_path, 'r') as f:
    content = f.read()

# Add includes
include_marker = '#include "third_party/tonic/dart_message_handler.h"'
include_addition = '''#include "third_party/tonic/dart_message_handler.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>'''
content = content.replace(include_marker, include_addition, 1)

# Add Koolbase fetch function before namespace flutter {
koolbase_code = '''
static bool Koolbase_FetchPatch(uint8_t* buf, size_t buf_len) {
  const char* host = "127.0.0.1";
  const char* port_str = "9876";
  const char* path = "/patch";

  struct addrinfo hints = {};
  struct addrinfo* res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port_str, &hints, &res) != 0) {
    printf("** Koolbase: DNS failed **\\n");
    return false;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    freeaddrinfo(res);
    printf("** Koolbase: socket failed **\\n");
    return false;
  }

  if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
    freeaddrinfo(res);
    close(sock);
    printf("** Koolbase: connect failed **\\n");
    return false;
  }
  freeaddrinfo(res);

  const char* request = "GET /patch HTTP/1.0\\r\\nHost: 127.0.0.1:9876\\r\\nConnection: close\\r\\n\\r\\n";
  send(sock, request, strlen(request), 0);

  char response[2048] = {};
  int total = 0;
  int n;
  while ((n = recv(sock, response + total, sizeof(response) - total - 1, 0)) > 0) {
    total += n;
  }
  close(sock);

  const char* header_end = strstr(response, "\\r\\n\\r\\n");
  if (header_end == nullptr) {
    printf("** Koolbase: bad HTTP response **\\n");
    return false;
  }

  const uint8_t* body = reinterpret_cast<const uint8_t*>(header_end + 4);
  size_t body_len = total - (header_end + 4 - response);

  if (body_len < buf_len) {
    printf("** Koolbase: response too short (%zu bytes) **\\n", body_len);
    return false;
  }

  memcpy(buf, body, buf_len);
  printf("** Koolbase: fetched %zu bytes **\\n", buf_len);
  fflush(stdout);
  return true;
}

namespace flutter {'''

content = content.replace('namespace flutter {', koolbase_code, 1)

# Inject hook call in LaunchRootIsolate
target_marker = '''bool RuntimeController::LaunchRootIsolate(
    const Settings& settings,
    const fml::closure& root_isolate_create_callback,
    std::optional<std::string> dart_entrypoint,
    std::optional<std::string> dart_entrypoint_library,
    const std::vector<std::string>& dart_entrypoint_args,
    std::unique_ptr<IsolateConfiguration> isolate_configuration) {
  if (root_isolate_.lock()) {'''

replacement = '''bool RuntimeController::LaunchRootIsolate(
    const Settings& settings,
    const fml::closure& root_isolate_create_callback,
    std::optional<std::string> dart_entrypoint,
    std::optional<std::string> dart_entrypoint_library,
    const std::vector<std::string>& dart_entrypoint_args,
    std::unique_ptr<IsolateConfiguration> isolate_configuration) {
  printf("** KOOLBASE HOOK HIT: LaunchRootIsolate **\\n");
  fflush(stdout);
  uint8_t patch_buf[128];
  Koolbase_FetchPatch(patch_buf, 128);
  if (root_isolate_.lock()) {'''

if target_marker not in content:
    print("ERROR: Could not find LaunchRootIsolate insertion point")
    exit(1)

content = content.replace(target_marker, replacement, 1)

with open(target_path, 'w') as f:
    f.write(content)

print("Koolbase Phase 2a hook applied to runtime_controller.cc")
