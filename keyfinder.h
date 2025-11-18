#ifndef KEYFINDER_H
#define KEYFINDER_H

#define BUFFER_SIZE 4096

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    unsigned long start_addr;
    unsigned long end_addr;
    char perms[5];
} memory_map_t;

typedef struct {
	bool found;
	unsigned int offset;
	uintptr_t address;
	uint8_t key[16];
} key_search_result_t;

key_search_result_t check_aes_128_key_expantion(uint8_t *buffer,size_t size,uintptr_t base_addr) ;
int find_pointer(uint8_t *buffer,size_t size,uintptr_t ptr);
void print_hex(unsigned char *buf,size_t s);
memory_map_t* parse_memory_maps(int pid,size_t * const len);
#endif
