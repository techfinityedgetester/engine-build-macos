#!/usr/bin/env python3

# Target file that IS compiled into FlutterMacOS.framework
target_path = "engine/src/flutter/runtime/runtime_controller.cc"

with open(target_path, 'r') as f:
    content = f.read()

# Add printf include at top (after last #include)
include_marker = '#include "third_party/tonic/dart_message_handler.h"'
include_addition = include_marker + '\n#include <cstdio>'
content = content.replace(include_marker, include_addition, 1)

# Find LaunchRootIsolate and inject printf as first statement
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
  if (root_isolate_.lock()) {'''

if target_marker not in content:
    print("ERROR: Could not find LaunchRootIsolate insertion point")
    exit(1)

content = content.replace(target_marker, replacement, 1)

with open(target_path, 'w') as f:
    f.write(content)

print("Koolbase Phase 1 hook applied to runtime_controller.cc")
