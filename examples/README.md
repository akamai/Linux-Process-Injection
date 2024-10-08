# Injection examples 
The following programs are examples that inject code into a remote process by using the primitives in this repository.
The injected payload is a shellcode that spawns bash.

## sample_target
This is a program that can be used as an example injection target.
To allow demonstrating some of the attacks, it:
- Maps a WX memory region to enable injection with process_vm_writev
- Waits inside a function to enable the stack hijacking primitives

## proc_writev_wx_ptrace_pokeuser
- Identify a WX memory region by parsing the process maps file
- Use process_vm_writev to write code into the identified region
- Use the POKEUSER ptrace request to change the value of RIP and point it to our code

## procfs_write_ptrace_setregs
- Identify an executable memory region by parsing the process maps file
- Use the procfs mem file to write code into the identified region
- Use the SETREGS ptrace request to change the value of RIP and point it to our code

## procfs_write_procfs_overwrite_rip
- Identify an executable memory region by parsing the process maps file
- Use the procfs mem file to write code into the identified region
- Identify the address of the next instruction by parsing the procfs syscall file
- Use the procfs mem file to replace the next instruction with a JMP instruction that transfers execution to our code

## ptrace_write_proc_writev_overwrite_stack
- Identify an executable memory region by parsing the process maps file
- Use the POKETEXT ptrace request to write code into the identified region
- Use process_vm_writev to overwrite a return address on the stack and point to our code

## proc_writev_overwrite_stack_rop
- Identify a writable memory region (no need for execute permissions!) by parsing the process maps file
- Use process_vm_writev to write our shellcode to the writable region
- Identify the base address of libc to calculate ROP gadget addresses
- Use process_vm_writev to overwrite the process stack with a ROP chain. The chain makes our shellcode executable and jumps to it.

## ptrace_write_proc_writev_overwrite_got
- Identify an executable memory region by parsing the process maps file
- Use the POKETEXT ptrace request to write code into the identified region
- Use process_vm_writev to overwrite function pointers inside the GOT and point to our code

