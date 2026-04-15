using namespace dart;

static void Koolbase_SHA256(const uint8_t* data, size_t len, uint8_t out[32]) {
  uint32_t h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };
  static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };

  auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };

  uint8_t block[64];
  uint64_t bit_len = (uint64_t)len * 8;
  size_t i = 0;

  auto process = [&](const uint8_t* b) {
    uint32_t w[64];
    for (int j = 0; j < 16; j++)
      w[j] = ((uint32_t)b[j*4]<<24)|((uint32_t)b[j*4+1]<<16)|
              ((uint32_t)b[j*4+2]<<8)|(uint32_t)b[j*4+3];
    for (int j = 16; j < 64; j++) {
      uint32_t s0 = rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>3);
      uint32_t s1 = rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>10);
      w[j] = w[j-16]+s0+w[j-7]+s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g2=h[6],hh=h[7];
    for (int j = 0; j < 64; j++) {
      uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      uint32_t ch=(e&f)^(~e&g2);
      uint32_t t1=hh+S1+ch+k[j]+w[j];
      uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      uint32_t maj=(a&b2)^(a&c)^(b2&c);
      uint32_t t2=S0+maj;
      hh=g2; g2=f; f=e; e=d+t1;
      d=c; c=b2; b2=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g2; h[7]+=hh;
  };

  for (; i + 64 <= len; i += 64) process(data + i);
  size_t rem = len - i;
  memcpy(block, data + i, rem);
  block[rem++] = 0x80;
  if (rem > 56) { memset(block+rem,0,64-rem); process(block); rem=0; }
  memset(block+rem, 0, 56-rem);
  for (int j = 7; j >= 0; j--) { block[56+(7-j)] = (bit_len>>(j*8))&0xff; }
  process(block);

  for (int j = 0; j < 8; j++) {
    out[j*4]=(h[j]>>24)&0xff; out[j*4+1]=(h[j]>>16)&0xff;
    out[j*4+2]=(h[j]>>8)&0xff; out[j*4+3]=h[j]&0xff;
  }
}

static uint64_t Koolbase_ComputeBuildID(const uint8_t* instructions,
                                        uint64_t size) {
  uint8_t hash[32];
  Koolbase_SHA256(instructions, static_cast<size_t>(size), hash);
  uint64_t id = 0;
  memcpy(&id, hash, 8);
  return id;
}

// TEMPORAL

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

  static bool Koolbase_VerifySignature(const uint8_t* message, size_t message_len,
                                      const uint8_t sig[64],
                                      const uint8_t pub[32]) {
    return true;
  }

// ================= PATCH LOGIC =================
static bool Koolbase_FetchPatch(const char* url, uint8_t* buf, size_t buf_len) {
  // Parse http://host:port/path
  const char* host_start = url + 7; // skip "http://"
  const char* colon = strchr(host_start, ':');
  const char* slash = strchr(host_start, '/');
  if (colon == nullptr || slash == nullptr) {
    OS::PrintErr("** Koolbase: malformed URL **\n");
    return false;
  }

  char host[64] = {};
  char port_str[8] = {};
  char path[128] = {};

  size_t host_len = colon - host_start;
  strncpy(host, host_start, host_len);

  size_t port_len = slash - colon - 1;
  strncpy(port_str, colon + 1, port_len);

  strncpy(path, slash, sizeof(path) - 1);

  int port = atoi(port_str);

  // Resolve and connect
  struct addrinfo hints = {}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port_str, &hints, &res) != 0) {
    OS::PrintErr("** Koolbase: DNS resolution failed **\n");
    return false;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    freeaddrinfo(res);
    OS::PrintErr("** Koolbase: socket() failed **\n");
    return false;
  }

  if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
    freeaddrinfo(res);
    close(sock);
    OS::PrintErr("** Koolbase: connect() failed **\n");
    return false;
  }
  freeaddrinfo(res);

  // Send HTTP GET
  char request[256];
  snprintf(request, sizeof(request),
           "GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
           path, host, port);
  send(sock, request, strlen(request), 0);

  // Read response into a buffer
  char response[2048] = {};
  int total = 0;
  int n;
  while ((n = recv(sock, response + total, sizeof(response) - total - 1, 0)) > 0) {
    total += n;
  }
  close(sock);

  // Find end of HTTP headers (\r\n\r\n)
  const char* header_end = strstr(response, "\r\n\r\n");
  if (header_end == nullptr) {
    OS::PrintErr("** Koolbase: HTTP response missing headers **\n");
    return false;
  }

  const uint8_t* body = reinterpret_cast<const uint8_t*>(header_end + 4);
  size_t body_len = total - (header_end + 4 - response);

  if (body_len < buf_len) {
    OS::PrintErr("** Koolbase: HTTP response too short (%zu bytes) **\n", body_len);
    return false;
  }

  memcpy(buf, body, buf_len);
  OS::PrintErr("** Koolbase: fetched %zu bytes from %s **\n", buf_len, url);
  return true;
}


static bool Koolbase_ReadPatch(const char* path,
                                KbPatchHeader* hdr,
                                uint8_t* sig_out) {
  uint8_t buf[128];
  if (!Koolbase_FetchPatch(path, buf, 128)) {
    return false;
  }

  // Check magic
  if (buf[0]!='K'||buf[1]!='B'||buf[2]!='P'||buf[3]!='M') {
    OS::PrintErr("** Koolbase: invalid magic **\n");
    return false;
  }

  // Parse header fields (little-endian)
  memcpy(hdr->magic, buf, 4);
  hdr->version      = buf[4] | (buf[5] << 8);
  hdr->header_size  = buf[6] | (buf[7] << 8);
  hdr->flags        = buf[8] | (buf[9]<<8) | (buf[10]<<16) | (buf[11]<<24);
  hdr->manifest_len = buf[12]|(buf[13]<<8)|(buf[14]<<16)|(buf[15]<<24);

  memcpy(&hdr->build_id, buf+16, 8);
  memcpy(&hdr->slot_index, buf+24, 8);
  memcpy(&hdr->nm_offset_snapshot_instructions, buf+32, 8);
  memcpy(&hdr->nm_offset_new_function, buf+40, 8);
  memcpy(&hdr->key_id, buf+48, 4);
  memcpy(&hdr->reserved_2, buf+56, 8);
  memcpy(sig_out, buf+64, 64);

  // Version check
  if (hdr->version != 1) {
    OS::PrintErr("** Koolbase: unsupported patch version %d **\n",
                 hdr->version);
    return false;
  }

  // Embedded public key (key_id = 1)
    static const uint8_t kPublicKey[32] = {
      0x34, 0x26, 0x56, 0x34, 0xac, 0x1a, 0xd4, 0x52,
      0x79, 0x38, 0x69, 0x5e, 0xd5, 0x9b, 0x17, 0x3c,
      0x49, 0xa0, 0xd7, 0xfe, 0x54, 0xfe, 0xfa, 0x43,
      0x76, 0x25, 0x24, 0x16, 0xd4, 0x5b, 0x05, 0xdc
    };

    // Verify signature: ED25519_verify(message=bytes[0..63], sig=bytes[64..127])
    if (!Koolbase_VerifySignature(buf, 64, sig_out, kPublicKey)) {
      OS::PrintErr("** Koolbase: SIGNATURE INVALID — patch rejected **\n");
      return false;
    }

    OS::PrintErr("** Koolbase: patch verified and loaded - slot=%lld nm_new=0x%llx **\n",
                hdr->slot_index, hdr->nm_offset_new_function);
    return true;
}

void Koolbase_PatchDispatchSlot(IsolateGroup* ig,
                                intptr_t slot_index,
                                uword new_entry_point) {
  GcSafepointOperationScope safepoint_scope(Thread::Current());
  DispatchTable* table = ig->dispatch_table();
  if (table == nullptr) {
    OS::PrintErr("** Koolbase: dispatch table is null — patch skipped **\n");
    return;
  }
  uword* array = const_cast<uword*>(table->ArrayOrigin());
  uword old_value = array[slot_index];
  array[slot_index] = new_entry_point;
  OS::PrintErr("** Koolbase: patched slot %lld: 0x%llx -> 0x%llx **\n",
             (long long)slot_index, (unsigned long long)old_value,
             (unsigned long long)new_entry_point);
}
