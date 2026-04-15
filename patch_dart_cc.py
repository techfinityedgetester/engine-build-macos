#!/usr/bin/env python3

dart_cc_path = "engine/src/flutter/third_party/dart/runtime/vm/dart.cc"

with open(dart_cc_path, 'r') as f:
    content = f.read()

# 1. Add system includes after #include "vm/dart.h"
includes = '#include <sys/socket.h>\n#include <netdb.h>\n#include <unistd.h>\n#include "vm/heap/safepoint.h"\n#include "vm/dispatch_table.h"\n'
content = content.replace('#include "vm/dart.h"\n', '#include "vm/dart.h"\n' + includes, 1)

# 2. Add Koolbase functions before namespace dart {
koolbase_functions = open('koolbase_functions.cc').read()
content = content.replace('namespace dart {\n', koolbase_functions + '\nnamespace dart {\n', 1)

# 3. Add hook before return Error::null() at end of InitializeIsolateGroup
koolbase_hook = open('koolbase_hook.cc').read()
target = '  return Error::null();\n}\n\nErrorPtr Dart::InitializeIsolate('
content = content.replace(target, koolbase_hook + '\n  return Error::null();\n}\n\nErrorPtr Dart::InitializeIsolate(', 1)

with open(dart_cc_path, 'w') as f:
    f.write(content)

print("Koolbase patches applied successfully")
