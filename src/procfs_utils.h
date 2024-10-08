#pragma once
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define PID_MAX 32768
#define PID_MAX_STR_LENGTH 64
#define MAX_LINE_LENGTH 1024
#define SIZE_OF_ADDRESS 12

long procfs_find_executable_region_start_address(long pid);
long procfs_find_executable_region_end_address(long pid);
long procfs_find_write_execute_region_start_address(long pid);
long procfs_find_libc_base(long pid);
long procfs_find_write_region_start_address(long pid);
long procfs_get_stack_return_address(long stack_address, long pid, long text_address, long text_size);
long procfs_get_stack_pointer(long pid);
long procfs_get_rip(long pid);
