#ifndef PROCESS_H
#define PROCESS_H

typedef struct {
    unsigned long start_addr;
    unsigned long end_addr;
    char perms[5];
} memory_map_t;

memory_map_t* parse_memory_maps(int pid,size_t * const len);

#endif
