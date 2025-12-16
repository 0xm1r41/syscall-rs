use core::arch::asm;
use syscall_rs::get_ssn;
use std::ptr::{null_mut, copy_nonoverlapping};
use std::ffi::c_void;

unsafe extern "system"{
    fn GetCurrentProcess() -> *mut c_void;
}

fn main () {
    unsafe{
         #[inline(always)]

         unsafe fn NtAllocateVirtualMemory(
                process_handle: isize,
                base_address: *mut *mut c_void,
                zero_bits: usize,
                region_size: *mut usize,
                allocation_type: u32,
                protect: u32,
            ) -> i32 {
                let mut status: i32;
                let syscall_num = get_ssn("NtAllocateVirtualMemory");
                asm!(
                    "sub rsp, 0x28",
                    "mov r10, rcx",
                    "mov [rsp+0x28], rsi",
                    "mov [rsp+0x30], rdi",
                    "mov eax, {syscall_num:e}",
                    "syscall",
                    "add rsp, 0x28",

                    syscall_num = in(reg) syscall_num as u32,
                    in("rcx") process_handle as usize,
                    in("rdx") base_address as usize,
                    in("r8") zero_bits,
                    in("r9") region_size as usize,
                    in("rsi") allocation_type as usize,
                    in("rdi") protect as usize,
                    lateout("rax") status,
                    clobber_abi("win64"),
                );

                status
            }

            unsafe fn NtWriteVirtualMemory(
                process_handle: isize,
                base_address: *mut c_void,
                buffer: *const c_void,
                number_of_bytes_to_write: usize,
                number_of_bytes_written: *mut usize,
            ) -> i32 {
                let mut status: i32;
                let syscall_num = get_ssn("NtWriteVirtualMemory");
                asm!(
                    "sub rsp, 0x28",
                    "mov [rsp+0x28], {bytes_written}",
                    "mov r10, rcx",
                    "mov eax, {syscall_num:e}",
                    "syscall",
                    "add rsp, 0x28",

                    syscall_num = in(reg) syscall_num as u32,
                    bytes_written = in(reg) number_of_bytes_written as usize,
                    in("rcx") process_handle as usize,
                    in("rdx") base_address as usize,
                    in("r8") buffer as usize,
                    in("r9") number_of_bytes_to_write as usize,
                    lateout("rax") status,
                    clobber_abi("win64"),  
                );
                status
            }

            unsafe fn NtProtectVirtualMemory(
                process_handle: isize,
                base_address: *mut *mut c_void,
                region_size: *mut usize,
                new_protect: u32,
                old_protect: *mut u32,
            ) -> i32 {
                let mut status: i32;
                let syscall_num = get_ssn("NtProtectVirtualMemory");

                asm!(
                    "sub rsp, 0x28",
                    "mov r10, rcx",
                    "mov [rsp + 0x28], rsi",
                    "mov eax, {syscall_num:e}",
                    "syscall",
                    "add rsp, 0x28",
                    syscall_num = in(reg) syscall_num as u32,
                    in("rcx") process_handle as usize,
                    in("rdx") base_address as usize,
                    in("r8") region_size as usize,
                    in("r9") new_protect as usize,
                    in("rsi") old_protect as usize,
                    lateout("rax") status,
                    clobber_abi("win64"),
                );
                status
            }

            unsafe fn NtCreateThreadEx(
                thread_handle: *mut *mut c_void,
                desired_access: u32,
                object_attributes: *mut c_void,
                process_handle: *mut c_void,
                start_address: *mut c_void,
                argument: *mut c_void,
                create_flags: u32,
                zero_bits: usize,
                stack_size: usize,
                maximum_stack_size: usize,
                attribute_list: *mut c_void,
            ) -> i32 {
                let mut status: i32;
                let syscall_num = get_ssn("NtCreateThreadEx");
                asm!(
                    "sub rsp, 0x70",
                    "mov r10, rcx",
                    "mov [rsp + 0x28], rsi",
                    "mov [rsp + 0x30], rdi",
                    "mov [rsp + 0x38], r11",
                    "mov [rsp + 0x40], r12",
                    "mov [rsp + 0x48], r13",
                    "mov [rsp + 0x50], r14",
                    "mov [rsp + 0x58], r15",
                    "mov eax, {syscall_num:e}",
                    "syscall",
                    "add rsp, 0x70",

                    syscall_num = in(reg) syscall_num,
                    in("rsi") start_address,
                    in("rdi") argument,
                    in("r11") create_flags as usize,
                    in("r12") zero_bits,
                    in("r13") stack_size,
                    in("r14") maximum_stack_size,
                    in("r15") attribute_list,
                    in("rcx") thread_handle as usize,
                    in("rdx") desired_access as usize,
                    in("r8") object_attributes as usize,
                    in("r9") process_handle as usize,
                    lateout("rax") status,
                    clobber_abi("win64"),
                );
                status
            }

            unsafe fn NtFreeVirtualMemory(
                process_handle: isize,
                base_address: *mut *mut c_void,
                region_size: *mut usize,
                free_type: u32
            ) -> i32 {
                let mut status: i32;
                let syscall_num = get_ssn("NtFreeVirtualMemory");

                asm!(
                    "sub rsp, 0x28",
                    "mov r10, rcx",
                    "mov eax, {syscall_num:e}",
                    "syscall",
                    "add rsp, 0x28",
                    syscall_num = in(reg) syscall_num,
                    in("rcx") process_handle as usize,
                    in("rdx") base_address as usize,
                    in("r8") region_size as usize,
                    in("r9") free_type as usize,
                    lateout("rax") status,
                    clobber_abi("win64"),
                );
                status
            }
     // Hello World Message Box shellcode       
     let payload: [u8; 433] = [
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x15, 0x66, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x0D, 0x52, 0x00, 0x00, 0x00, 0xE8, 0x9E, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF8,
    0x48, 0x8D, 0x0D, 0x5D, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x8D, 0x15, 0x5F, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x0D, 0x4D, 0x00, 0x00, 0x00, 0xE8, 0x7F, 0x00, 0x00, 0x00, 0x4D, 0x33, 0xC9,
    0x4C, 0x8D, 0x05, 0x61, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x4E, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC9,
    0xFF, 0xD0, 0x48, 0x8D, 0x15, 0x56, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x0A, 0x00, 0x00, 0x00,
    0xE8, 0x56, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC9, 0xFF, 0xD0,
    
    
    0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x44, 0x4C, 0x4C, 0x00,
    0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00,
    0x55, 0x53, 0x45, 0x52, 0x33, 0x32, 0x2E, 0x44, 0x4C, 0x4C, 0x00,
    0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00,
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00,
    0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x00,
    0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00,
    
   
    0x48, 0x83, 0xEC, 0x28, 0x65, 0x4C, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
    0x4D, 0x8B, 0x40, 0x18, 0x4D, 0x8D, 0x60, 0x10, 0x4D, 0x8B, 0x04, 0x24,
    0xFC, 0x49, 0x8B, 0x78, 0x60, 0x48, 0x8B, 0xF1, 0xAC, 0x84, 0xC0, 0x74, 0x26,
    0x8A, 0x27, 0x80, 0xFC, 0x61, 0x7C, 0x03, 0x80, 0xEC, 0x20, 0x3A, 0xE0, 0x75, 0x08,
    0x48, 0xFF, 0xC7, 0x48, 0xFF, 0xC7, 0xEB, 0xE5,
    0x4D, 0x8B, 0x00, 0x4D, 0x3B, 0xC4, 0x75, 0xD6,
    0x48, 0x33, 0xC0, 0xE9, 0xA7, 0x00, 0x00, 0x00,
    
    0x49, 0x8B, 0x58, 0x30, 0x44, 0x8B, 0x4B, 0x3C, 0x4C, 0x03, 0xCB,
    0x49, 0x81, 0xC1, 0x88, 0x00, 0x00, 0x00,
    0x45, 0x8B, 0x29, 0x4D, 0x85, 0xED, 0x75, 0x08,
    0x48, 0x33, 0xC0, 0xE9, 0x85, 0x00, 0x00, 0x00,
    
    0x4E, 0x8D, 0x04, 0x2B, 0x45, 0x8B, 0x71, 0x04, 0x4D, 0x03, 0xF5,
    0x41, 0x8B, 0x48, 0x18, 0x45, 0x8B, 0x50, 0x20, 0x4C, 0x03, 0xD3,
    0xFF, 0xC9, 0x4D, 0x8D, 0x0C, 0x8A, 0x41, 0x8B, 0x39,
    0x48, 0x03, 0xFB, 0x48, 0x8B, 0xF2, 0xA6, 0x75, 0x08,
    0x8A, 0x06, 0x84, 0xC0, 0x74, 0x09, 0xEB, 0xF5, 0xE2, 0xE6,
    0x48, 0x33, 0xC0, 0xEB, 0x4E,
    
    0x45, 0x8B, 0x48, 0x24, 0x4C, 0x03, 0xCB,
    0x66, 0x41, 0x8B, 0x0C, 0x49,
    0x45, 0x8B, 0x48, 0x1C, 0x4C, 0x03, 0xCB,
    0x41, 0x8B, 0x04, 0x89,
    0x49, 0x3B, 0xC5, 0x7C, 0x2F,
    0x49, 0x3B, 0xC6, 0x73, 0x2A,
    
    0x48, 0x8D, 0x34, 0x18,
    0x48, 0x8D, 0x7C, 0x24, 0x30,
    0x4C, 0x8B, 0xE7,
    0xA4,
    0x80, 0x3E, 0x2E, 0x75, 0xFA,
    0xA4,
    0xC7, 0x07, 0x44, 0x4C, 0x4C, 0x00,
    0x49, 0x8B, 0xCC,
    0x41, 0xFF, 0xD7,
    0x49, 0x8B, 0xCC,
    0x48, 0x8B, 0xD6,
    0xE9, 0x14, 0xFF, 0xFF, 0xFF,
    
    0x48, 0x03, 0xC3,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
];

     let mut base_address: *mut c_void = null_mut();
     let mut size: usize = payload.len(); 
     let process: *mut c_void = GetCurrentProcess();

      let alloc = NtAllocateVirtualMemory(
                process as isize,
                &mut base_address,
                0,
                &mut size,
                0x3000,
                0x04,
            );
        if alloc != 0 as i32 {
            println!("Failed to allocate memory: {:X}", alloc);
        } else {
            println!("Successfully allocated {} bytes at {:?}", size, base_address);
        }

        let mut written: usize = 0;
        let buffer: *const c_void = payload.as_ptr() as *const c_void;
        let write = NtWriteVirtualMemory(
            process as isize,
            base_address,
            buffer,
            payload.len(),
            &mut written,
        );
        if write != 0 as i32 {
            println!("Failed to write into memory: {:X}", write);
        } else {
            println!("Successfully written into memory!");
        }

        let mut old_protect: u32 = 0;
        let protection = NtProtectVirtualMemory(
            process as isize,
            &mut base_address,
            &mut size,
            0x20,
            &mut old_protect,
        );
        if protection != 0 as i32 {
            println!("Failed to flip page protection: {:X}", protection);
        } else {
            println!("Flipped page protection - executing soon!");
        }

        let mut thread_handle: *mut c_void = null_mut();
        let exec = NtCreateThreadEx(
            &mut thread_handle,
            0x1FFFFF,
            null_mut(),
            usize::MAX as *mut c_void,
            base_address,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );
        if exec != 0 as i32{
            println!("Failed to execute payload: {:X}", exec);
        } else {
            println!("Executed payload successfully - dont click on Ok (it'll close in 5sec)");
        }
      
      std::thread::sleep(std::time::Duration::from_secs(5));
      
      let free = NtFreeVirtualMemory(
            process as isize,
            &mut base_address,
            &mut size,
            0x8000
        );
        if free != 0 as i32 {
            println!("Failed to free memory: {:X}", free);
       } else {
            println!("Successfully freed {}", size);
        }
    }
}


 