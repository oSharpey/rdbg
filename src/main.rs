/*
RDBG - a simple debugger written in Rust
Structure of the project has been helped by the following resources:
    https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/
    https://carstein.github.io/2022/05/29/rust-system-programming-2.html
    https://carstein.github.io/2022/09/11/rust-system-programming-3.html
    https://medium.com/@lizrice/a-debugger-from-scratch-part-1-7f55417bc85f
*/

extern crate capstone;
extern crate linenoise;
extern crate nix;


// Nix crate provivdes safer alternatives to libc, and is used for system calls like ptrace, fork
// and wait

use nix::libc::personality;
use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult};

use std::env;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

use crate::debugger::Debugger;
mod debugger;

const NO_ASLR: u64 = 0x0040000;

fn run_child(proc_name: &str) {
    // let the process be ptraced
    ptrace::traceme().unwrap();
    // execute the target program
    Command::new(proc_name).exec();
    exit(0);
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
            // Disabling ASLR makes it easier to test with setting breakpoints
            unsafe { personality(NO_ASLR) };
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
