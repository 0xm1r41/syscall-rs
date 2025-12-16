use core::{arch::asm, ptr};

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct LdrDataTableEntry {
    reserved1: [u8; 0x30],
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    reserved2: [u8; 0x10],
    reserved3: [usize; 2],
    reserved4: [u8; 8],
}

#[inline(always)]
pub unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    #[cfg(target_arch = "x86_64")]
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

pub unsafe fn find_module_base(peb: *mut u8, dll_name: &str) -> Option<*mut u8> {
    let ldr = *(peb.add(0x18) as *const *const u8);
    let module_list = *(ldr.add(0x10) as *const *const u8); 

    let mut current = *(module_list as *const *const u8);

    loop {
        let entry = current as *const LdrDataTableEntry;
        let base_dll_name = &(*entry).base_dll_name;

        // Validate UNICODE_STRING
        if base_dll_name.buffer.is_null() || base_dll_name.length == 0 {
            current = *(current as *const *const u8);
            if current == module_list {
                break;
            }
            continue;
        }

        let name_slice = core::slice::from_raw_parts(
            base_dll_name.buffer,
            (base_dll_name.length / 2) as usize,
        );
        let name = String::from_utf16_lossy(name_slice).to_lowercase();

        if name == dll_name.to_lowercase() {
            return Some((*entry).dll_base);
        }

        current = *(current as *const *const u8);
        if current == module_list {
            break;
        }
    }

    None
}

pub unsafe fn find_export(base: *mut u8, func_name: &str) -> Option<*mut u8> {
    let dos_header = base as *const u16;
    let e_lfanew = *dos_header.add(0x3C / 2) as usize;
    let nt_headers = base.add(e_lfanew);
    let optional_header = nt_headers.add(0x18);

    let export_rva = *(optional_header.add(0x70) as *const u32) as usize;
    if export_rva == 0 {
        return None; 
    }

    let export_dir = base.add(export_rva);
    let names_rva = *(export_dir.add(0x20) as *const u32) as usize;
    let ordinals_rva = *(export_dir.add(0x24) as *const u32) as usize;
    let funcs_rva = *(export_dir.add(0x1C) as *const u32) as usize;
    let num_names = *(export_dir.add(0x18) as *const u32) as usize;

    for i in 0..num_names {
        let name_rva = *(base.add(names_rva + i * 4) as *const u32) as usize;
        let name_ptr = base.add(name_rva) as *const u8;

        let mut name_buf = Vec::new();
        let mut offset = 0;
        loop {
            let c = *name_ptr.add(offset);
            if c == 0 {
                break;
            }
            name_buf.push(c);
            offset += 1;
        }

        if String::from_utf8_lossy(&name_buf) == func_name {
            let ordinal = *(base.add(ordinals_rva + i * 2) as *const u16) as usize;
            let func_rva = *(base.add(funcs_rva + ordinal * 4) as *const u32) as usize;
            return Some(base.add(func_rva));
        }
    }
    None
}

#[inline(always)]
pub unsafe fn get_ssn(func_name: &str) -> u32 {
    let peb = get_peb();
    let ntdll_base = match find_module_base(peb, "ntdll.dll") {
        Some(base) => base,
        None => panic!("[-] Failed to locate ntdll.dll"),
    };

    let func_ptr = match find_export(ntdll_base, func_name) {
        Some(ptr) => ptr,
        None => panic!("[-] Failed to resolve export: {}", func_name),
    };

    let ssn_ptr = func_ptr.add(4) as *const u32;
    ptr::read_unaligned(ssn_ptr)
}
