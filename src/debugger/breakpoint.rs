use nix::sys::ptrace;
use nix::unistd::Pid;
use std::ffi::c_void;

#[derive(Debug)]
pub struct Breakpoint {
    b_addr: u64,
    target_pid: Pid,
    saved_data: u64,
    pub enabled: bool,
}
impl Breakpoint {
    pub fn new(addr: u64, pid: Pid) -> Breakpoint {
        Breakpoint {
            b_addr: addr,
            target_pid: pid,
            saved_data: 0,
            enabled: false,
        }
    }

    pub fn enable(&mut self) {
        let try_read = || -> Result<u64, nix::Error> {
            let value = ptrace::read(self.target_pid, self.b_addr as *mut c_void)?;
            Ok(value as u64)
        };

        if let Err(_) = try_read() {
            println!("Failed to read memory at address 0x{:x}", self.b_addr);
            return;
        }

        let value = try_read().unwrap();
        self.saved_data = value;
        let bp = (value & (u64::MAX ^ 0xff)) | 0xcc;

        unsafe {
            ptrace::write(
                self.target_pid,
                self.b_addr as *mut c_void,
                bp as *mut c_void,
            )
            .unwrap();
        }
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        unsafe {
            ptrace::write(
                self.target_pid,
                self.b_addr as *mut c_void,
                self.saved_data as *mut c_void,
            )
            .unwrap();
        }
        self.enabled = false;
    }
}
