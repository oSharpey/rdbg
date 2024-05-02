use nix::sys::ptrace;
use nix::unistd::Pid;

// Pretty self expanitory module, used for getting and setting registers

pub fn get_reg_by_name(reg_name: &str, pid: Pid) -> u64 { 
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

pub fn set_register_by_name(reg_name: &str, value: u64, pid: Pid) {
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

pub fn dump_regs(pid: Pid) {
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

pub fn set_rip(pid: Pid, value: u64) {
    let mut regs = ptrace::getregs(pid).unwrap();
    regs.rip = value;
    ptrace::setregs(pid, regs).unwrap();
}
