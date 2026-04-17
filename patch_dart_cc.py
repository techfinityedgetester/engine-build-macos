#!/usr/bin/env python3

target_path = "engine/src/flutter/runtime/dart_isolate.cc"

with open(target_path, 'r') as f:
    content = f.read()

# Add includes
include_marker = '#include "third_party/tonic/scopes/dart_isolate_scope.h"'
include_addition = include_marker + '''
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

struct KbPatchHeader {
  uint8_t  magic[4];
  uint16_t version;
  uint16_t header_size;
  uint32_t flags;
  uint32_t manifest_len;
  uint64_t build_id;
  int64_t  slot_index;
  uint64_t nm_offset_snapshot_instructions;
  uint64_t nm_offset_new_function;
  uint32_t key_id;
  uint32_t reserved_1;
  uint64_t reserved_2;
};

namespace flutter {'''

content = content.replace('namespace flutter {', koolbase_code, 1)

# Inject hook inside PrepareForRunningFromPrecompiledCode (right after phase_ = Phase::Ready;)
target_marker = '''  const fml::closure& isolate_create_callback =
      GetIsolateGroupData().GetIsolateCreateCallback();
  if (isolate_create_callback) {
    isolate_create_callback();
  }

  phase_ = Phase::Ready;
  return true;
}

bool DartIsolate::LoadKernel('''

replacement = '''  const fml::closure& isolate_create_callback =
      GetIsolateGroupData().GetIsolateCreateCallback();
  if (isolate_create_callback) {
    isolate_create_callback();
  }

  phase_ = Phase::Ready;

  // ==== KOOLBASE PATCH HOOK ====
  printf("** KOOLBASE HOOK HIT: PrepareForRunningFromPrecompiledCode **\\n");
  fflush(stdout);
  uint8_t patch_buf[128];
  if (Koolbase_FetchPatch(patch_buf, 128)) {
    KbPatchHeader hdr;
    memcpy(hdr.magic, patch_buf, 4);
    if (hdr.magic[0]=='K'&&hdr.magic[1]=='B'&&hdr.magic[2]=='P'&&hdr.magic[3]=='M') {
      hdr.version      = patch_buf[4] | (patch_buf[5] << 8);
      hdr.header_size  = patch_buf[6] | (patch_buf[7] << 8);
      memcpy(&hdr.flags, patch_buf+8, 4);
      memcpy(&hdr.manifest_len, patch_buf+12, 4);
      memcpy(&hdr.build_id, patch_buf+16, 8);
      memcpy(&hdr.slot_index, patch_buf+24, 8);
      memcpy(&hdr.nm_offset_snapshot_instructions, patch_buf+32, 8);
      memcpy(&hdr.nm_offset_new_function, patch_buf+40, 8);
      memcpy(&hdr.key_id, patch_buf+48, 4);
      memcpy(&hdr.reserved_2, patch_buf+56, 8);

      printf("** Koolbase: parsed patch - slot=%lld nm_new=0x%llx **\\n",
             (long long)hdr.slot_index,
             (unsigned long long)hdr.nm_offset_new_function);
      fflush(stdout);
    } else {
      printf("** Koolbase: invalid magic number **\\n");
      fflush(stdout);
    }
  }
  // ==== END KOOLBASE ====

  return true;
}

bool DartIsolate::LoadKernel('''

if target_marker not in content:
    print("ERROR: Could not find PrepareForRunningFromPrecompiledCode insertion point")
    exit(1)

content = content.replace(target_marker, replacement, 1)

with open(target_path, 'w') as f:
    f.write(content)

print("Koolbase Phase 2b hook applied to dart_isolate.cc")
