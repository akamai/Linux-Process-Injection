#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include "procfs_utils.h"

int procfs_proc_mem_write(long address, long pid, const char *payload);
int procfs_proc_mem_exec(long address, long pid);
