# syscall-rs

Direct Windows syscall execution in Rust. Walks the PEB to locate ntdll, resolves exports manually, extracts syscall numbers at runtime, and invokes NT APIs without touching monitored stubs.

## What It Does

This library gives you raw syscall access without depending on the Windows API. It walks the Process Environment Block to find ntdll.dll, parses PE headers to resolve exports, extracts syscall numbers from function prologues, and executes syscalls directly through inline assembly. No API calls, no hooks, just direct kernel interaction.

**PEB Walking** - Traverses the Process Environment Block to locate ntdll.dll without calling LoadLibrary or any loader functions. The PEB contains a linked list of all loaded modules, and we walk it manually to find what we need.

**Manual Export Resolution** - Parses PE headers and export tables directly from memory. No GetProcAddress, no import tables. We read the DOS header, find the NT headers, locate the export directory, and resolve function addresses ourselves.

**Runtime SSN Extraction** - Reads syscall numbers from function prologues at offset +4. Every ntdll syscall stub starts with `mov r10, rcx; mov eax, <syscall_number>`. We just read that number directly from memory at runtime, so it works across Windows versions even when Microsoft changes syscall numbers.

**Direct Syscalls** - Executes NT APIs via inline assembly, bypassing all hooks. We set up registers according to the x64 Windows calling convention, load the syscall number into eax, and execute the syscall instruction. EDRs monitoring ntdll stubs see nothing.

**Complete Memory Operations** - Supports the critical NT APIs you actually need: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtFreeVirtualMemory. Everything required for basic shellcode execution without touching the Windows API.

## Why This Exists

EDRs hook ntdll stubs and monitor LoadLibrary/GetProcAddress. Traditional shellcode loaders that call VirtualAlloc or CreateThread get caught immediately because those API calls go through hooked functions. This implementation sidesteps that entire detection surface.

We never call Windows APIs for module or function resolution. We read syscall numbers directly from ntdll's mapped image in memory. We make syscalls via inline assembly with proper x64 calling convention. The only thing that can see this is kernel-mode callbacks, and even those only see the syscall itself - not which userland function you "called" to get there.

This is the same technique commercial C2 frameworks use, but implemented in Rust because I wanted memory safety while doing extremely unsafe things. The irony isn't lost on me.

## Implementation Details

**SSN Resolution**

The core of this is reading the syscall number from ntdll at runtime:
```rust
let peb = get_peb();                           // Read from GS:[0x60]
let ntdll = find_module_base(peb, "ntdll");    // Walk PEB_LDR_DATA
let func = find_export(ntdll, "NtAllocate");   // Parse export table
let ssn = *(func + 4);                         // Extract syscall number
```

We read the PEB from the gs segment register at offset 0x60. That gives us the PEB_LDR_DATA structure which contains InMemoryOrderModuleList - a linked list of every loaded module. We walk that list comparing module names (case-insensitive, UTF-16) until we find ntdll.dll.

Once we have ntdll's base address, we parse its PE headers. Read the DOS header, find e_lfanew, jump to the NT headers, locate the export directory RVA, and then walk the export table. We compare exported function names until we find the one we want, then resolve its RVA to get the function address.

The syscall number is always at offset +4 in the function prologue. The first 4 bytes are `mov r10, rcx` (0x4C 0x8B 0xD1), and the next 5 bytes are `mov eax, <ssn>` (0xB8 followed by the 4-byte syscall number). We just read that dword and we're done.

**Syscall Invocation**

The tricky part is handling different parameter counts correctly. NT APIs can take anywhere from 4 to 11 parameters. x64 Windows calling convention puts the first 4 arguments in registers (rcx, rdx, r8, r9) and the rest on the stack. Before the syscall instruction, we have to move rcx to r10 (that's what the syscall stub does), load the syscall number into eax, and make sure the stack is properly aligned.

The inline assembly looks different for each parameter count because Rust's asm! macro requires you to explicitly specify which registers you're using and where data comes from. It's verbose but correct.

Stack alignment matters. The stack must be 16-byte aligned before the syscall instruction, and you need shadow space (32 bytes) for the first 4 parameters even though they're in registers. Get this wrong and you'll crash or corrupt data.

## Usage

Basic example of allocating memory, writing shellcode, making it executable, and running it:
```rust
use syscall_rs::*;

unsafe {
    let alloc = NtAllocateVirtualMemory(...);
    
    // Write your shellcode to addr
    let write = NtWriteVirtualMemory(...);
    
    // Make it executable
    let protection = NtProtectVirtualMemory(...);
    
    // Run it in a new thread
    let exec = NtCreateThreadEx(...);

    // Free memory
    let free = NtFreeVirtualMemory(...)
}
```

See `examples/demo.rs` for a complete shellcode loader that actually works. It handles all the error checking and proper cleanup I'm skipping here for brevity.

## Build

Standard Rust build process:
```bash
cargo build --release --example demo
target/release/examples/demo.exe
```

The demo executable loads a message box shellcode (or whatever you generate with msfvenom) and executes it entirely through syscalls. No VirtualAlloc, no CreateThread, just NT APIs.

## Technical Notes

Some things to know before you use this:

**x64 Windows only** - The PEB structure, calling convention, and syscall mechanism are all x64-specific. This won't work on 32-bit or ARM. Porting would require rewriting basically everything.

**PEB structure offsets are stable** - Microsoft has kept these consistent across Windows versions because too much software depends on them. The offset to PEB_LDR_DATA and the structure of LIST_ENTRY haven't changed since Windows Vista. That said, no guarantees for future Windows versions.

**SSN extraction assumes standard prologue** - We're reading bytes at a fixed offset assuming ntdll functions start with `mov r10, rcx; mov eax, <ssn>`. If Microsoft changes the stub format (unlikely but possible), this breaks. Some security products have experimented with hot-patching ntdll to change these patterns, which would also break this.

**Shellcode compatibility** - Some shellcode generators produce position-independent code that assumes it's running in a certain context. If you're loading Meterpreter or Beacon payloads, make sure they're configured with `EXITFUNC=thread` so they exit cleanly instead of trying to kill the whole process.

**No error handling in examples** - The usage example above is simplified. Real code needs to check return values (NT APIs return NTSTATUS codes) and handle failures gracefully. The demo does this properly.

## Why Rust

I could have written this in C, and it would have been shorter. But Rust's type system catches memory safety bugs at compile time, which matters when you're doing low-level manipulation of process memory structures. The alternative is debugging access violations and heap corruption at runtime, which is tedious.

The inline assembly syntax is more verbose in Rust than C, but the safety guarantees around it are worth it. Plus, Rust's ownership model makes it harder to accidentally leak memory or leave dangling pointers, which is surprisingly easy to do when you're manually managing NT API allocations.

## License

MIT - do whatever you want with it.

## Disclaimer

This is for educational purposes and authorized security research only. Don't use this to compromise systems you don't own or have permission to test. Unauthorized access is illegal, and I'm not responsible for what you do with this code.

If you're using this professionally, make sure you have proper authorization and document everything. Cover your ass.
