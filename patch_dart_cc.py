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
#include <unistd.h>
#include <sys/mman.h>'''
content = content.replace(include_marker, include_addition, 1)

# Koolbase helpers + struct
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

// Scan memory pages near snapshot_data for our price marker and patch it
static bool Koolbase_FindAndPatchMarker(const uint8_t* snapshot_data,
                                        size_t scan_size,
                                        const char* new_price) {
  const char* marker = "KBPRICE@@@";
  size_t marker_len = 10;

  // Scan forward from snapshot_data
  for (size_t i = 0; i < scan_size - marker_len - 3; i++) {
    bool match = true;
    for (size_t j = 0; j < marker_len; j++) {
      if (snapshot_data[i+j] != marker[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      // Found it — patch the 3 digits at i+10
      uint8_t* target = (uint8_t*)(snapshot_data + i + 10);

      // Make page writable
      size_t page_size = 4096;
      uintptr_t page_start = (uintptr_t)target & ~(page_size - 1);
      if (mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_WRITE) != 0) {
        printf("** Koolbase: mprotect failed **\\n");
        return false;
      }

      target[0] = new_price[0];
      target[1] = new_price[1];
      target[2] = new_price[2];

      // Restore protection
      mprotect((void*)page_start, page_size * 2, PROT_READ);

      printf("** Koolbase: patched marker at offset 0x%lx **\\n", (unsigned long)i);
      fflush(stdout);
      return true;
    }
  }
  printf("** Koolbase: marker not found in scan **\\n");
  return false;
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

# Inject hook in PrepareForRunningFromPrecompiledCode
target_marker = '''  phase_ = Phase::Ready;
  return true;
}

bool DartIsolate::LoadKernel('''

replacement = '''  phase_ = Phase::Ready;

  // ==== KOOLBASE PATCH HOOK ====
  printf("** KOOLBASE HOOK HIT: PrepareForRunningFromPrecompiledCode **\\n");
  fflush(stdout);
  uint8_t patch_buf[128];
  if (Koolbase_FetchPatch(patch_buf, 128)) {
    if (patch_buf[0]=='K'&&patch_buf[1]=='B'&&patch_buf[2]=='P'&&patch_buf[3]=='M') {
      // New price is stored in bytes 40-42
      char new_price[4] = {0};
      new_price[0] = patch_buf[40];
      new_price[1] = patch_buf[41];
      new_price[2] = patch_buf[42];
      printf("** Koolbase: new price from patch: %s **\\n", new_price);

      // Get snapshot data pointer
      auto snapshot = GetIsolateGroupData().GetIsolateSnapshot();
      auto data_mapping = snapshot->GetDataMapping();
      const uint8_t* snapshot_data = data_mapping;

      // Scan 16MB from snapshot_data to find the marker
      Koolbase_FindAndPatchMarker(snapshot_data, 16 * 1024 * 1024, new_price);
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

print("Koolbase Phase 2c hook applied to dart_isolate.cc")
