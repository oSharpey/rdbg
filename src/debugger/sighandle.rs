use nix::libc::{c_int, siginfo_t};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;

const SI_KERNEL: c_int = 128;
const TRAP_BRKPT: c_int = 1;
const TRAP_TRACE: c_int = 2;

pub fn wait_for_signal() {
    match wait() {
        Ok(status) => {
            match status {
                WaitStatus::Stopped(pid, signal) => {
                    match signal {
                        Signal::SIGTRAP => {
                            //println!("Process {} stopped by SIGTRAP", pid);
                            let siginfo = ptrace::getsiginfo(pid).unwrap();
                            //println!("Signal info: {:?}", siginfo);
                            handle_sigtrap(pid, siginfo);
                        }
                        Signal::SIGSEGV => {
                            let regs = ptrace::getregs(pid).unwrap();
                            println!("Process {} stopped by SIGSEGV", pid);
                            println!("SEGMENTATION FAULT at address 0x{:x}", regs.rip);
                        }
                        _ => {
                            println!("Process {} stopped by signal {:?}", pid, signal);
                        }
                    }
                }
                _ => {
                    println!("Status: {:?}", status);
                }
            }
        }
        Err(err) => {
            println!("Wait failed: {}", err);
        }
    }
}

fn handle_sigtrap(pid: Pid, siginfo: siginfo_t) {
    let mut regs = ptrace::getregs(pid).unwrap();
    match siginfo.si_code {
        SI_KERNEL => {
            //println!("Process {} stopped by kernel", pid);
        }
        TRAP_BRKPT => {
            regs.rip -= 1;
            ptrace::setregs(pid, regs).unwrap();
            println!(
                "Process {} stopped by breakpoint at address 0x{:x}",
                pid, regs.rip
            );
        }
        TRAP_TRACE => {}
        _ => {
            println!("Process {} stopped by unknown signal", pid);
        }
    }
}
