#ifndef KEYFINDER_H
#define KEYFINDER_H

#define BUFFER_SIZE (4096)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
  uintptr_t start_addr;
  uintptr_t end_addr;
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

//https://github.com/openssl/openssl/blob/b372b1f76450acdfed1e2301a39810146e28b02c/include/crypto/evp.h#L131
typedef struct evp_cipher_st {
  int nid;
  int block_size;
  int key_len;
  int iv_len;
} evp_cipher_st_t;


void print_hex(unsigned char *buf,size_t s);
void print_key(aes_128_key_t *aes_key);
int open_memory(int pid);
int close_memory(int fd);
void scan_aes_keys(int mem_fd,memory_map_list_t *maps,key_list_t *keylist);
void scan_iv_keys(int mem_fd,memory_map_list_t *maps,key_list_t *keylist);
uintptr_t find_iv_addr(uint8_t *buffer,size_t size,uintptr_t ptr,uintptr_t offset);
ssize_t read_offset(int fd,void *buf,size_t count,off_t offset);

memory_map_list_t* parse_memory_maps(int pid);
void free_memory_map_list(memory_map_list_t *list);

aes_128_key_t* find_aes_128_keys(uint8_t *buffer,size_t size,uintptr_t base_addr) ;
void add_aes_128_key(key_list_t *list,aes_128_key_t *key);
key_list_t *init_key_list(size_t capacity);
void free_key_list(key_list_t *list);
#endif
