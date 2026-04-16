IsolateGroup* ig = T->isolate_group();
if (ig != nullptr &&
    kernel_buffer == nullptr &&
    snapshot_data != nullptr) {
  KbPatchHeader hdr;
  uint8_t sig[64];
  if (Koolbase_ReadPatch("http://127.0.0.1:9876/patch", &hdr, sig)) {
    const uint8_t* instructions = ig->source()->snapshot_instructions;
    if (instructions != nullptr) {
      uint64_t instr_size = hdr.reserved_2;
      uint64_t runtime_build_id = Koolbase_ComputeBuildID(instructions, instr_size);
      if (runtime_build_id != hdr.build_id) {
        OS::PrintErr("** Koolbase: BUILD ID MISMATCH **\n");
      } else {
        OS::PrintErr("** Koolbase: build_id verified (0x%llx) **\n",
                     (unsigned long long)runtime_build_id);
        if (ig->dispatch_table() != nullptr) {
          uword library_base = reinterpret_cast<uword>(instructions) -
                               hdr.nm_offset_snapshot_instructions;
          uword new_entry = library_base + hdr.nm_offset_new_function;
          Koolbase_PatchDispatchSlot(ig, hdr.slot_index, new_entry);
        } else {
          OS::PrintErr("** Koolbase: dispatch table null, patch deferred **\n");
        }
      }
    }
  }
}
