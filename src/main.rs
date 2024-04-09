extern crate capstone;
extern crate linenoise;
extern crate nix;

use nix::libc::{c_int, personality, siginfo_t};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use nix::unistd::{fork, ForkResult};

use capstone::prelude::*;
use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

const SI_KERNEL: c_int = 128;
const TRAP_BRKPT: c_int = 1;
const TRAP_TRACE: c_int = 2;

struct Debugger {
    target_pid: Pid,
    bps: HashMap<u64, Breakpoint>,
}
impl Debugger {
    fn new(pid: Pid) -> Debugger {
        Debugger {
            target_pid: pid,
            bps: HashMap::new(),
        }
    }

    fn run(&mut self) {
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
        // prints the current stack frame
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
        let bp_addr = get_rip(self.target_pid) - 1;
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
        let bp_addr = get_rip(self.target_pid) - 1;
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
                println!("\nCommands:\n     continue (c) - continue execution\n     break (b) <addr> - set breakpoint\n     quit (q) - quit debugger\n");
            }
            _ => {
                println!("Unknown command");
            }
        }
    }
}

#[derive(Debug)]
struct Breakpoint {
    b_addr: u64,
    target_pid: Pid,
    saved_data: u64,
    enabled: bool,
}
impl Breakpoint {
    fn new(addr: u64, pid: Pid) -> Breakpoint {
        Breakpoint {
            b_addr: addr,
            target_pid: pid,
            saved_data: 0,
            enabled: false,
        }
    }

    fn enable(&mut self) {
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

    fn disable(&mut self) {
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

fn run_child(proc_name: &str) {
    // let the process be ptraced
    ptrace::traceme().unwrap();
    // execute the target program
    Command::new(proc_name).exec();
    exit(0);
}

fn get_reg_by_name(reg_name: &str, pid: Pid) -> u64 {
    let regs = ptrace::getregs(pid).unwrap();
    match reg_name {
        "rax" => regs.rax,
        "rbx" => regs.rbx,
        "rcx" => regs.rcx,
        "rdx" => regs.rdx,
        "rdi" => regs.rdi,
        "rsi" => regs.rsi,
        "rbp" => regs.rbp,
        "rsp" => regs.rsp,
        "rip" => regs.rip,
        "r8" => regs.r8,
        "r9" => regs.r9,
        "r10" => regs.r10,
        "r11" => regs.r11,
        "r12" => regs.r12,
        "r13" => regs.r13,
        "r14" => regs.r14,
        "r15" => regs.r15,
        "eflags" => regs.eflags,
        _ => 0,
    }
}

fn set_register_by_name(reg_name: &str, value: u64, pid: Pid) {
    let mut regs = ptrace::getregs(pid).unwrap();
    match reg_name {
        "rax" => regs.rax = value,
        "rbx" => regs.rbx = value,
        "rcx" => regs.rcx = value,
        "rdx" => regs.rdx = value,
        "rdi" => regs.rdi = value,
        "rsi" => regs.rsi = value,
        "rbp" => regs.rbp = value,
        "rsp" => regs.rsp = value,
        "rip" => regs.rip = value,
        "r8" => regs.r8 = value,
        "r9" => regs.r9 = value,
        "r10" => regs.r10 = value,
        "r11" => regs.r11 = value,
        "r12" => regs.r12 = value,
        "r13" => regs.r13 = value,
        "r14" => regs.r14 = value,
        "r15" => regs.r15 = value,
        "eflags" => regs.eflags = value,
        _ => {}
    }
    ptrace::setregs(pid, regs).unwrap();
}

fn dump_regs(pid: Pid) {
    let regs = ptrace::getregs(pid).unwrap();
    println!("\n------------- Registers -------------");
    println!(
        "RAX: 0x{:x} \nRBX: 0x{:x} \nRCX: 0x{:x} \nRDX: 0x{:x}",
        regs.rax, regs.rbx, regs.rcx, regs.rdx
    );
    println!(
        "RDI: 0x{:x} \nRSI: 0x{:x} \nRBP: 0x{:x} \nRSP: 0x{:x}",
        regs.rdi, regs.rsi, regs.rbp, regs.rsp
    );
    println!(
        "RIP: 0x{:x} \nR8: 0x{:x} \nR9: 0x{:x} \nR10: 0x{:x}",
        regs.rip, regs.r8, regs.r9, regs.r10
    );
    println!(
        "R11: 0x{:x} \nR12: 0x{:x} \nR13: 0x{:x} \nR14: 0x{:x}",
        regs.r11, regs.r12, regs.r13, regs.r14
    );
    println!("R15: 0x{:x} \nFLAGS: 0x{:x}", regs.r15, regs.eflags);
    println!("-------------------------------------\n");
}

fn get_rip(pid: Pid) -> u64 {
    let regs = ptrace::getregs(pid).unwrap();
    regs.rip
}

fn set_rip(pid: Pid, value: u64) {
    let mut regs = ptrace::getregs(pid).unwrap();
    regs.rip = value;
    ptrace::setregs(pid, regs).unwrap();
}

fn wait_for_signal() {
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

fn disassemble(pid: Pid) {
    let target_name = env::args().nth(1).unwrap();
    let mut target_bytes = fs::File::open(&target_name).unwrap();
    let mut buff: Vec<u8> = Vec::new();
    let rip = get_rip(pid);

    let _ = target_bytes.read_to_end(&mut buff);

    let elf = object::File::parse(&buff[..]).unwrap();
    let text_section = elf.section_by_name(".text").unwrap();
    let text_bytes = text_section.data().unwrap();

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Masm)
        .detail(true)
        .build()
        .unwrap();

    let text_start = text_section.address();
    let asm = cs.disasm_all(&text_bytes, text_start).unwrap();
    let start_index = asm.iter().position(|i| i.address() >= rip).unwrap_or(0);
    
    println!("\n--------------- Disassembly ---------------");

    for i in asm.iter().skip(start_index).take(10) {
        // Make it look pretty when printing the disas
        // instr_hex needed so that we can print the bytes of the instruction as hex otherwise it'll be an ugly [u8] printed like [ff, ff, ff, ff]
        let instr_hex = i
            .bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");
        println!(
            "0x{:x}: {:<15} {:<10} {}",
            i.address(),
            instr_hex,
            i.mnemonic().unwrap(),
            i.op_str().unwrap()
        );
    }
    println!("-------------------------------------------\n");
}

fn main() {
    println!(
        r"
$$$$$$$\  $$\       $$$$$$\   $$$$$$\        $$$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\  
$$  __$$\ $$ |     $$  __$$\ $$  __$$\       $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |     $$ /  \__|$$ /  \__|      $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ /  \__|
$$$$$$$  |$$ |     $$ |      \$$$$$$\        $$$$$$$  |$$ |  $$ |$$$$$$$\ |$$ |$$$$\ 
$$  ____/ $$ |     $$ |       \____$$\       $$  __$$< $$ |  $$ |$$  __$$\ $$ |\_$$ |
$$ |      $$ |     $$ |  $$\ $$\   $$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ |      $$$$$$$$\\$$$$$$  |\$$$$$$  |      $$ |  $$ |$$$$$$$  |$$$$$$$  |\$$$$$$  |
\__|      \________|\______/  \______/       \__|  \__|\_______/ \_______/  \______/ 
"
    );

    println!("\n Welcome to rdbg - a simple debugger \n");

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 || args[1] == "--help" || args[1] == "-h" {
        println!("Usage: {} <program>", args[0]);
        println!("Usage: {} --help", args[0]);
        return;
    }

    let target_name = args[1].clone();

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let no_aslr: u64 = 0x0040000;
            unsafe { personality(no_aslr) };
            run_child(&target_name);
        }
        Ok(ForkResult::Parent { child }) => {
            let mut rdbg = Debugger::new(child);
            rdbg.run();
        }
        Err(err) => {
            println!("Fork failed: {}", err);
        }
    }
}
