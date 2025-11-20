#ifndef KEYFINDER_H
#define KEYFINDER_H

#define BUFFER_SIZE (4096)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
  unsigned long start_addr;
  unsigned long end_addr;
  char perms[5];
} memory_map_t;

typedef struct {
  memory_map_t *maps;
  size_t count;
  size_t capacity;
} memory_map_list_t;

typedef struct {
  unsigned int offset;
  uintptr_t address;
  uint8_t key[16];
} aes_128_key_t;

typedef struct {
  aes_128_key_t *keys;
  size_t count;
  size_t capacity;
} key_list_t;

aes_128_key_t* find_aes_128_keys(uint8_t *buffer,size_t size,uintptr_t base_addr) ;
int find_pointer(uint8_t *buffer,size_t size,uintptr_t ptr);
void print_hex(unsigned char *buf,size_t s);
memory_map_list_t* parse_memory_maps(int pid);
void add_aes_128_key(key_list_t *list,aes_128_key_t *key);
key_list_t *init_key_list(size_t capacity);
#endif
