#pragma once
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>


int ptrace_poketext_write(long pid, long address, const char* payload);
int ptrace_setregs_exec(long pid, long address, bool attached);
int ptrace_pokeuser_exec(long pid, long address, bool attached);
