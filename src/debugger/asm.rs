use nix::sys::ptrace;
use nix::unistd::Pid;

use capstone::prelude::*;
use object::{Object, ObjectSection};

use std::env;
use std::fs;
use std::io::Read;

pub fn disassemble(pid: Pid) {
    let target_name = env::args().nth(1).unwrap();
    let mut target_bytes = fs::File::open(&target_name).unwrap();
    let mut buff: Vec<u8> = Vec::new();
    //let rip = get_rip(pid);
    let rip = ptrace::getregs(pid).unwrap().rip - 1;

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
