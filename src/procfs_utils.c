#include "procfs_utils.h"


/*
  Extract the permissions string of a memory region by parsing a given line from the procfs maps file
  
  line: a maps line to be parsed
*/
char *get_permissions_from_line(char *line) {
    int first_space = -1;
    int second_space = -1;
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == ' ' && first_space == -1) {
            first_space = i + 1;
        }
        else if (line[i] == ' ' && first_space != -1) {
            second_space = i;
            break;
        }
    }
    
    if (first_space != -1 && second_space != -1 && second_space > first_space) {
        char *permissions = malloc(second_space - first_space + 1);
        if (permissions == NULL) {
            fprintf(stderr, "Could not allocate memory. Aborting.\n");
            return NULL;
        }
        for (size_t i = first_space, j = 0; i < (size_t)second_space; i++, j++) {
            permissions[j] = line[i];
        }
        permissions[second_space - first_space] = '\0';
        return permissions;
    }
    return NULL;

}

/*
  Extract the end address of a memory region by parsing a given line from the procfs maps file
  
  line: a maps line to be parsed
*/
long get_end_address_from_maps_line(char *line) {

    char *start_address = strchr(line, '-') + 1;
    char *address_line = malloc(SIZE_OF_ADDRESS + 1);
    memset(address_line, 0, SIZE_OF_ADDRESS + 1);
    memcpy(address_line, start_address, SIZE_OF_ADDRESS);
    long address = strtol(address_line, (char **) NULL, 16);

    return address;
}

/*
  Extract the start address of a memory region by parsing a given line from the procfs maps file
  
  line: a maps line to be parsed
*/

long get_start_address_from_maps_line(char *line) {

    char *address_line = malloc(SIZE_OF_ADDRESS + 1);
    memset(address_line, 0, SIZE_OF_ADDRESS + 1);
    memcpy(address_line, line, SIZE_OF_ADDRESS);
    long address = strtol(address_line, (char **) NULL, 16);
    return address;
}


/*
  Parse the procfs maps file and identify a memory region address based on the given parameters.
  
  pid: the pid of the process we are scanning.
  get_region_start_address: true if we want the start address of the region, false if we want the end address
  permissions_string: a substring of the required memory region permission string. for example: rw, wx
*/
long procfs_find_memory_region(long pid, bool get_region_start_address, char *permissions_string) {
    size_t maps_file_name_length = PID_MAX_STR_LENGTH + 12;
    char *maps_file_name = malloc(maps_file_name_length);
    if (snprintf(maps_file_name, maps_file_name_length, "/proc/%ld/maps", pid) < 0) {
        fprintf(stderr, "Could not use snprintf: %s", strerror(errno));
        return -1;
    }

    FILE *maps_file = fopen(maps_file_name, "r");
    if (maps_file == NULL) {
        fprintf(stderr, "Could not open %s file. Aborting.\n", maps_file_name);
        return -1; 
    }
    
    char *maps_line = NULL;
    size_t maps_line_length = 0;
    while (getline(&maps_line, &maps_line_length, maps_file) != -1) {
        char *permissions = get_permissions_from_line(maps_line);
        
        if (permissions == NULL) {
            continue;
        } else if (strstr(permissions, permissions_string) != NULL) {
            free(permissions);
            break;
        }
        free(permissions);
    }
    long address;
    
    if (get_region_start_address)
    {
        address = get_start_address_from_maps_line(maps_line);
    }
    else
    {
        address = get_end_address_from_maps_line(maps_line);
    }
    free(maps_line);
    
    return address;
}

/*
  Parse the procfs maps file and identify a memory region address based on the given parameters.
  
  pid: the pid of the process we are scanning.
*/
long procfs_find_libc_base(long pid) {
    size_t maps_file_name_length = PID_MAX_STR_LENGTH + 12;
    char *maps_file_name = malloc(maps_file_name_length);
    if (snprintf(maps_file_name, maps_file_name_length, "/proc/%ld/maps", pid) < 0) {
        fprintf(stderr, "Could not use snprintf: %s", strerror(errno));
        return -1;
    }

    FILE *maps_file = fopen(maps_file_name, "r");
    if (maps_file == NULL) {
        fprintf(stderr, "Could not open %s file. Aborting.\n", maps_file_name);
        return -1; 
    }
    
    char *maps_line = NULL;
    size_t maps_line_length = 0;
    while (getline(&maps_line, &maps_line_length, maps_file) != -1) {
        if (strstr(maps_line, "libc.so") != NULL) {
            break;
        }

    }

    long address = get_start_address_from_maps_line(maps_line);

    free(maps_line);
    
    return address;
}

/*
  Find the start address of the first executable memory region for a process with a given pid.
  
  pid: the process to scan
*/
long procfs_find_executable_region_start_address(long pid)
{
    return procfs_find_memory_region(pid, true, "r-x");
}

/*
  Find the end address of the first executable memory region for a process with a given pid.
  
  pid: the process to scan
*/
long procfs_find_executable_region_end_address(long pid)
{
    return procfs_find_memory_region(pid, false, "r-x");
}

/*
  Find the start address of the first write + execute memory region for a process with a given pid.
  
  pid: the process to scan
*/
long procfs_find_write_execute_region_start_address(long pid)
{
   return procfs_find_memory_region(pid, true, "wx");
}

/*
  Find the start address of the first writeable memory region for a process with a given pid.
  
  pid: the process to scan
*/
long procfs_find_write_region_start_address(long pid)
{
   return procfs_find_memory_region(pid, true, "rw");
}

/*
  Find the stack pointer of a process with the given pid by scanning the procfs syscall file.
  
  pid: the process to scan
*/
long procfs_get_stack_pointer(long pid) {

    char path[256];
    char *endptr;
    
    snprintf(path, sizeof(path), "/proc/%ld/syscall", pid);
    FILE *file = fopen(path, "r"); 
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    fgets(line, sizeof(line), file);
    fclose(file);
    
    char *token = strtok(line, " "); // Splitting by space
    char *last_chunk, *prev_chunk;

    while (token != NULL) {
        if (last_chunk != NULL)
        {
          prev_chunk = last_chunk;
        }
        
        last_chunk = token;
        token = strtok(NULL, " ");
    }
    return strtol(prev_chunk, &endptr, 16);
}


/*
  Find the instruction pointer of a process with the given pid by scanning the procfs syscall file.
  
  pid: the process to scan
*/
long procfs_get_rip(long pid) {

    char path[256];
    char *endptr;
    
    snprintf(path, sizeof(path), "/proc/%ld/syscall", pid);
    FILE *file = fopen(path, "r"); 
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    fgets(line, sizeof(line), file);
    fclose(file);
    
    char *token = strtok(line, " "); // Splitting by space
    char *last_chunk;

    while (token != NULL) {
        last_chunk = token;
        token = strtok(NULL, " ");
    }
    return strtol(last_chunk, &endptr, 16);
}

/*
  Scan the stack of a given process and find a value representing a return address inside the executable text section.
  return the address of this value on the stack.
  
  pid: the process to scan
*/
long procfs_get_stack_return_address(long stack_address, long pid, long text_address, long text_size) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/proc/%ld/mem", pid);
    FILE *file = fopen(filepath, "r+");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (fseek(file, stack_address, SEEK_SET) != 0) {
        perror("Error setting file offset");
        fclose(file);
        return 1;
    }

    long stack_content;

    while (file)
    {
    
    // get the next value from the stack
    fread(&stack_content, sizeof(long), 1, file);
    stack_address += sizeof(long);
    
    	// check if the value is a memory address inside the process text section
        if ((stack_content > text_address) && ((stack_content - text_address) < text_size))
        {
    	    stack_address -= sizeof(long);
    	    return stack_address;
        }
    
    }
    
    fclose(file);
    return 0;
}
