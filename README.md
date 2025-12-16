# syscall-rs

Direct Windows syscall execution in Rust. Walks the PEB to locate ntdll, resolves exports manually, extracts syscall numbers at runtime, and invokes NT APIs without touching monitored stubs.

## What It Does

- **PEB Walking**: Traverses Process Environment Block to locate ntdll.dll without calling any APIs
- **Manual Export Resolution**: Parses PE headers and export tables directly from memory
- **Runtime SSN Extraction**: Reads syscall numbers from function prologues at offset +4
- **Direct Syscalls**: Executes NT APIs via inline assembly, bypassing all hooks
- **Complete Memory Operations**: VirtualAlloc, VirtualProtect, CreateThread, VirtualFree through syscalls

## Why

EDRs hook ntdll stubs and monitor LoadLibrary/GetProcAddress. This implementation:
- Never calls Windows APIs for module/function resolution
- Reads syscall numbers directly from ntdll's mapped image
- Makes syscalls via inline asm with proper x64 calling convention

## Implementation Details

**SSN Resolution**
```rust
let peb = get_peb();                           // Read from GS:[0x60]
let ntdll = find_module_base(peb, "ntdll");    // Walk PEB_LDR_DATA
let func = find_export(ntdll, "NtAllocate");   // Parse export table
let ssn = *(func + 4);                         // Extract syscall number
```

**Syscall Invocation**
- Supports 4-11 parameter NT APIs
- Proper stack alignment for x64 Windows calling convention
- Args 1-4 in registers (rcx, rdx, r8, r9)
- Args 5-11 on stack at correct offsets

## Usage
```rust
use syscall_rs::*;

unsafe {
    let ssn = get_ssn("NtAllocateVirtualMemory");
    let addr = NtAllocateVirtualMemory(size, MEM_COMMIT, PAGE_READWRITE);
    // ... write shellcode ...
    NtProtectVirtualMemory(addr, size, PAGE_EXECUTE_READ);
    NtCreateThreadEx(addr);
}
```

See `examples/demo.rs` for complete shellcode loader.

## Build
```bash
cargo build --release --example demo
target/release/examples/demo.exe
```

## Technical Notes

- Only works on x64 Windows
- PEB structure offsets are stable across Windows versions
- SSN extraction assumes standard ntdll prologue (`mov r10, rcx; mov eax, <ssn>`)
- Some shellcode may require `EXITFUNC=thread` for clean exit

## License

MIT

## Disclaimer

Educational and authorized security research only.
