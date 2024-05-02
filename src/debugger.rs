use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::ffi::c_void;
use std::process::exit;

use crate::debugger::asm::disassemble;
use crate::debugger::breakpoint::Breakpoint;
use crate::debugger::registers::{dump_regs, get_reg_by_name, set_register_by_name, set_rip};
use crate::debugger::sighandle::get_proc_status;

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
            // Hashmap to store breakpoints, used for faster lookup of breakpoints
            bps: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        get_proc_status();
        loop {
            // Linenoise used for user input handling
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
        let read_result = ptrace::read(self.target_pid, addr as *mut c_void);
        let read_mem = match read_result {
            Ok(value) => value as u64,
            Err(_) => {
                println!("Failed to read memory at address 0x{:x}", addr);
                return;
            }
        };
        println!("Memory at address 0x{:x}: 0x{:x}", addr, read_mem);
    }

    fn write_memory(&self, addr: u64, value: u64) {
        unsafe {
            let write_result =
                ptrace::write(self.target_pid, addr as *mut c_void, value as *mut c_void);
            let _ = match write_result {
                Ok(_) => value,
                Err(_) => {
                    println!("Failed to write memory at address 0x{:x}", addr);
                    return;
                }
            };
        }
        println!("Memory at address 0x{:x} set to 0x{:x}", addr, value);
    }

    fn set_breakpoint(&mut self, addr: u64) {
        let mut breakpoint = Breakpoint::new(addr, self.target_pid);
        breakpoint.enable();
        self.bps.insert(addr, breakpoint);
    }

    fn step_over_bp(&mut self) {
        // have to take 1 off the rip to get the correct address
        let bp_addr = ptrace::getregs(self.target_pid).unwrap().rip - 1;
        if let Some(bp) = self.bps.get_mut(&bp_addr) {
            if bp.enabled {
                set_rip(self.target_pid, bp_addr);
                bp.disable();
                ptrace::step(self.target_pid, None).unwrap();
                get_proc_status();
                bp.enable();
            }
        }
    }

    fn single_step(&self) {
        ptrace::step(self.target_pid, None).unwrap();
        get_proc_status();
    }

    fn step_with_bp_check(&mut self) {
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
                get_proc_status();
            }
            "break" | "b" => {
                if cmd.len() < 2 {
                    println!("Usage: break(b) <addr>");
                    return;
                }
                println!("Break");
                let raw_addr = cmd[1].trim_start_matches("0x");
                let addr_result = u64::from_str_radix(raw_addr, 16);
                let addr = match addr_result {
                    Ok(value) => value,
                    Err(_) => {
                        println!("Invalid address");
                        return;
                    }
                };

                self.set_breakpoint(addr);
            }
            "bd" => {
                println!("Delete breakpoint");
                let raw_addr = cmd[1].trim_start_matches("0x");
                let addr_result = u64::from_str_radix(raw_addr, 16);
                let addr = match addr_result {
                    Ok(value) => value,
                    Err(_) => {
                        println!("Invalid address");
                        return;
                    }
                };
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
                    if cmd.len() < 3 {
                        println!("Usage: register(r) read <register>");
                        return;
                    }
                    println!(
                        "{:?}: 0x{:x}",
                        cmd[2],
                        get_reg_by_name(cmd[2], self.target_pid)
                    );
                } else if cmd[1] == "write" {
                    if cmd.len() < 4 {
                        println!("Usage: register(r) write <register> <value>");
                        return;
                    }
                    let raw_value = cmd[3].trim_start_matches("0x");
                    let value_result = u64::from_str_radix(raw_value, 16);
                    let value = match value_result {
                        Ok(value) => value,
                        Err(_) => {
                            println!("Invalid value");
                            return;
                        }
                    };
                    set_register_by_name(cmd[2], value, self.target_pid);
                } else {
                    println!("Usage: register(r) read/wrtie <register> OR register(r) dump");
                }
            }
            "memory" | "m" => {
                if cmd.len() < 3 {
                    println!(
                        "Usage: memory(m) read <address> OR memory(m) write <address> <value>"
                    );
                    return;
                }
                // assuming the correct address format here
                let raw_addr = cmd[2].trim_start_matches("0x");
                let addr_result = u64::from_str_radix(raw_addr, 16);
                let addr = match addr_result {
                    Ok(value) => value,
                    Err(_) => {
                        println!("Invalid address");
                        return;
                    }
                };

                if cmd[1] == "read" {
                    // Read memory from an address,
                    self.read_memory(addr);
                } else if cmd[1] == "write" {
                    let raw_value = cmd[3].trim_start_matches("0x");
                    let value_result = u64::from_str_radix(raw_value, 16);
                    let value = match value_result {
                        Ok(value) => value,
                        Err(_) => {
                            println!("Invalid value");
                            return;
                        }
                    };
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
                let try_kill = ptrace::kill(self.target_pid);
                match try_kill {
                    Ok(_) => {}
                    Err(_) => {
                        println!();
                    }
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
