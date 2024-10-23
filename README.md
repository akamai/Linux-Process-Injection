# Linux Process Injection
This repository contains proof-of-concept implementations of various Linux process injection primitives.

This code is meant to provide simple examples of injection techniques in action, allowing defenders to understand how they work and to test detections.
For the sake of simplicity and to keep the code as benign as possible, the implemented techniques **don't handle process recovery** - meaning that the target process will likely crash after the injected payload finishes.

The primitives are implemented using 3 methods: *ptrace*, *procfs mem*, and *process_vm_writev*.
For each of them, 2 types of primitives were implemented:
- **Write primitives**: intended to write the code into the remote process
- **Execution primitives**: intended to transfer execution to the injected code

  
These primitives can be combined freely to create "custom" injection variations.

The following primitives are implemented:

## ptrace

**ptrace_poketext_write** 

Write code into a remote process by using the ptrace POKETEXT request.

**ptrace_setregs_exec**

Hijack the execution flow of a remote process by using the ptrace SETREGS request to modify the process RIP register.

**ptrace_pokeuser_exec**

Hijack the execution flow of a remote process by using the ptrace POKEUSER request to modify the process RIP register by accessing the process user area.

## procfs mem
**procfs_proc_mem_write**


Write code into a remote process by editing its procfs mem file.

**procfs_proc_mem_exec**

Hijack the execution flow of a remote process by editing its procfs mem file. 
This is implemented by:
1. Identifying the address currently inside RIP
2. Inject a small stub to that address that performs a JMP to the address of our payload.
Alternatively, it is possible to use the *procfs_proc_mem_write* function to directly write our code to the address of RIP.

## process_vm_writev
**process_vm_writev_write**

Write code into a remote process by using the process_vm_writev syscall. This requires writing to a writable memory region.

**process_vm_writev_stack_overwrite_exec**

Hijack the execution flow of a remote process by overwriting a return address on its stack.

**process_vm_writev_stack_overwrite_rop**

Execute code in the remote process by overwriting its stack with a ROP chain.
This method relies on hardcoded addresses of gadgets, please modify them to make it work on your machine.

**process_vm_writev_got_overwrite_exec**

Hijack the execution flow of a remote process by overwriting function pointers inside its GOT.
This implementation is crude, and will simply overwrite the first 100 pointers.
To make this method more reliable, it is required to parse the GOT and target specific functions.

-------

## Usage
This repository includes a few examples that use the implemented primitives to perfrom injection attacks.
To build them, run the *make* command inside the main folder.

Implementations of the different primitives can be found in the *src* folder. To use them in your own code to create custom implementations, simply include the relevant header file.
Please use the *examples* folder for additional reference. 

-------

## Credits
Some of the code was based on the following repositories:

https://github.com/W3ndige/linux-process-injection

https://github.com/gaffe23/linux-inject/tree/master

The inspiration for this project:

https://github.com/SafeBreach-Labs/pinjectra

-------

# License 

Copyright 2024 Akamai Technologies Inc.

Akamai follows ethical security research principles and makes this software available so that others can assess and improve the security of their own environments.  
Akamai does not condone malicious use of the software; the user is solely responsible for their conduct.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
