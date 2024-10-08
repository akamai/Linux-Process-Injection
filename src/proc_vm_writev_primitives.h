#pragma once
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include "procfs_utils.h"

int process_vm_writev_write(long pid, long address, void *data, int data_len);
int process_vm_writev_stack_overwrite_exec(long pid, long address);
int process_vm_writev_stack_overwrite_rop(long pid, long address, long libc_base);
int process_vm_writev_got_overwrite_exec(long pid, long address);
