use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::ffi::c_void;
use std::process::exit;

use crate::debugger::asm::disassemble;
use crate::debugger::breakpoint::Breakpoint;
use crate::debugger::registers::{dump_regs, get_reg_by_name, set_register_by_name, set_rip};
use crate::debugger::sighandle::wait_for_signal;

mod asm;
mod breakpoint;
mod registers;
mod sighandle;

pub struct Debugger {
    pub target_pid: Pid,
    bps: HashMap<u64, Breakpoint>,
}
impl Debugger {
    pub fn new(pid: Pid) -> Debugger {
        Debugger {
            target_pid: pid,
            bps: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        wait_for_signal();
        loop {
            let line = linenoise::input("rdbg> ");
            match line {
                None => break,
                Some(cmd) => {
                    self.command(cmd.as_ref());
                    linenoise::history_add(cmd.as_ref());
                }
            }
        }
    }

    fn print_stack_frame(&self) {
        // prints the current stack frame (rbp to rsp)
        let regs = ptrace::getregs(self.target_pid).unwrap();
        let rbp = regs.rbp;
        let rsp = regs.rsp;

        println!("Base Pointer: 0x{:x} \nStack Pointer: 0x{:x}", rbp, rsp);
        println!("\n--------------- Stack ---------------");
        let mut current_frame = rsp;
        while current_frame <= rbp {
            let value = ptrace::read(self.target_pid, current_frame as *mut c_void).unwrap();
            println!("0x{:x}:   0x{:x}", current_frame, value);
            current_frame += 8;
        }
        println!("-------------------------------------\n");
    }

    fn read_memory(&self, addr: u64) {
        let try_read = || -> Result<u64, nix::Error> {
            let value = ptrace::read(self.target_pid, addr as *mut c_void)?;
            Ok(value as u64)
        };

        if let Err(_) = try_read() {
            println!("Failed to read memory at address 0x{:x}", addr);
            return;
        }

        let value = try_read().unwrap();
        println!("Memory at address 0x{:x}: 0x{:x}", addr, value);
    }

    fn write_memory(&self, addr: u64, value: u64) {
        let try_write = || -> Result<(), nix::Error> {
            // This feels dangerous but lets go with it
            unsafe {
                ptrace::write(self.target_pid, addr as *mut c_void, value as *mut c_void)?;
            }
            Ok(())
        };
        if let Err(_) = try_write() {
            println!("Failed to write memory at address 0x{:x}", addr);
            return;
        }
        println!("Memory at address 0x{:x} set to 0x{:x}", addr, value);
    }

    fn set_breakpoint(&mut self, addr: u64) {
        let mut breakpoint = Breakpoint::new(addr, self.target_pid);
        breakpoint.enable();
        self.bps.insert(addr, breakpoint);
    }

    fn step_over_bp(&mut self) {
        // let bp_addr = get_rip(self.target_pid) - 1;
        let bp_addr = ptrace::getregs(self.target_pid).unwrap().rip - 1;
        if let Some(bp) = self.bps.get_mut(&bp_addr) {
            if bp.enabled {
                set_rip(self.target_pid, bp_addr);
                bp.disable();
                ptrace::step(self.target_pid, None).unwrap();
                wait_for_signal();
                bp.enable();
            }
        }
    }

    fn single_step(&self) {
        ptrace::step(self.target_pid, None).unwrap();
        wait_for_signal();
    }

    fn step_with_bp_check(&mut self) {
        //let bp_addr = get_rip(self.target_pid) - 1;
        let bp_addr = ptrace::getregs(self.target_pid).unwrap().rip - 1;
        if self.bps.contains_key(&bp_addr) {
            self.step_over_bp();
        } else {
            self.single_step();
        }
    }

    fn command(&mut self, line: &str) {
        let cmd = line.split_whitespace().collect::<Vec<&str>>();
        let prefix = cmd[0];

        //println!("Command: {:?}", prefix);

        match prefix {
            "continue" | "c" => {
                println!("Continue");
                self.step_over_bp();
                ptrace::cont(self.target_pid, None).unwrap();
                wait_for_signal();
            }
            "break" | "b" => {
                println!("Break");
                let raw_addr = cmd[1].trim_start_matches("0x");
                let addr = u64::from_str_radix(raw_addr, 16).unwrap();
                self.set_breakpoint(addr);
            }
            "bd" => {
                println!("Delete breakpoint");
                let raw_addr = cmd[1].trim_start_matches("0x");
                let addr = u64::from_str_radix(raw_addr, 16).unwrap();
                if let Some(bp) = self.bps.get_mut(&addr) {
                    bp.disable();
                    self.bps.remove(&addr);
                }
            }
            "register" | "r" => {
                if cmd.len() < 2 {
                    println!("Usage: register(r) read/wrtie <register> OR register(r) dump");
                    return;
                }
                if cmd[1] == "dump" {
                    dump_regs(self.target_pid);
                } else if cmd[1] == "read" {
                    println!(
                        "{:?}: 0x{:x}",
                        cmd[2],
                        get_reg_by_name(cmd[2], self.target_pid)
                    );
                } else if cmd[1] == "write" {
                    let raw_value = cmd[3].trim_start_matches("0x");
                    let value = u64::from_str_radix(raw_value, 16).unwrap();
                    set_register_by_name(cmd[2], value, self.target_pid);
                } else {
                    println!("Usage: register(r) read/wrtie <register> OR register(r) dump");
                }
            }
            "memory" | "m" => {
                if cmd.len() < 2 {
                    println!(
                        "Usage: memory(m) read <address> OR memory(m) write <address> <value>"
                    );
                    return;
                }
                //being very dumb here with assuming the correct address format
                let raw_addr = cmd[2].trim_start_matches("0x");
                let addr = u64::from_str_radix(raw_addr, 16).unwrap();

                if cmd[1] == "read" {
                    // Read memory from an address,
                    self.read_memory(addr);
                } else if cmd[1] == "write" {
                    let raw_value = cmd[3].trim_start_matches("0x");
                    let value = u64::from_str_radix(raw_value, 16).unwrap();
                    self.write_memory(addr, value);
                } else {
                    println!(
                        "Usage: memory(m) read <address> OR memory(m) write <address> <value>"
                    );
                }
            }
            "stepi" | "si" => {
                println!("Step once");
                self.step_with_bp_check();
            }

            "stack" | "st" => {
                self.print_stack_frame();
            }

            "disas" | "d" => {
                disassemble(self.target_pid);
            }

            "quit" | "q" => {
                println!("Quit");

                // handle the error if the process is already dead from continue
                let try_kill = || -> Result<(), nix::Error> {
                    ptrace::kill(self.target_pid)?;
                    Ok(())
                };

                if let Err(_) = try_kill() {
                    println!();
                }
                exit(0);
            }
            "help" | "h" => {
                println!(
                    " 
COMMANDS
       continue (c)
           Continue execution.

       break (b) <addr>
           Set breakpoint.

       register (r)
           read <register>
               Read register.
           write <register> <value>
               Write register.
           dump
               Dump all registers.

       memory (m)
           read <addr>
               Read memory at address.
           write <addr> <value>
               Write memory at address.

       stepi (si)
           Step one instruction.

       stack (st)
           Print current stack frame.

       disas (d)
           Disassemble 10 instructions from current instruction pointer.

       quit (q)
           Quit debugger.

       help (h)
           Print this help menu.
"
                );
            }
            _ => {
                println!("Unknown command");
            }
        }
    }
}
