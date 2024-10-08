CC := gcc
CFLAGS := -Wall

# Source files
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

# Example binaries
EXAMPLES := procfs_write_procfs_overwrite_rip \
            procfs_write_ptrace_setregs \
            proc_writev_wx_ptrace_pokeuser \
            ptrace_write_proc_writev_overwrite_stack \
            ptrace_write_proc_writev_overwrite_got \
            proc_writev_overwrite_stack_rop \
            sample_target 
            

all: $(EXAMPLES)


%: examples/%.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o src/*.o $(EXAMPLES)
