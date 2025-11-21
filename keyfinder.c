#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<stdbool.h>
#include<sys/stat.h>
#include<sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "keyfinder.h"
#include "aes.h"

#define KEY_SIZE 16
static const int NUMBER_OF_ROUND_KEYS=11;
static const int ROUND_KEY_BLOCK_SIZE=KEY_SIZE*NUMBER_OF_ROUND_KEYS;

void print_hex(unsigned char *buf,size_t s) 
{
  for (int i=0; i<s; i++) {
    printf("%02x,",buf[i]);
  }
  printf("\n");
}

void print_key(aes_128_key_t *aes_key) 
{
  printf("aes block is found\n");
  printf("offset in block=%d\n",aes_key->offset);
  printf("key address=%lx\n",aes_key->address);
  printf("key=");
  print_hex(aes_key->key,16);
}

//TODO:what if key starts at the end of current buffer and goes beyond the next?
aes_128_key_t* find_aes_128_keys(uint8_t *buffer,size_t size,uintptr_t base_addr) 
{
  uint8_t candidate[KEY_SIZE]={0};
  uint8_t key[KEY_SIZE]={0};
  for (int i=0; i<size-(ROUND_KEY_BLOCK_SIZE-1); i++) {
    memcpy(candidate,buffer+i,KEY_SIZE);
    memcpy(key,candidate,KEY_SIZE);
    for (int round=1; round<NUMBER_OF_ROUND_KEYS; round++) {
      expand_key(round,key);
      if(memcmp(buffer+i+round*KEY_SIZE,key,KEY_SIZE)!=0)
        break;
      if (round==NUMBER_OF_ROUND_KEYS-1) {
	aes_128_key_t* res = malloc(sizeof(*res));
        res->offset=i;
        res->address = base_addr+i;
        memcpy(res->key,candidate,KEY_SIZE); 
        return res;
      }
    }
  }
  return NULL;
}

uintptr_t find_iv_addr(uint8_t *buffer,size_t size,uintptr_t ptr,unsigned long offset)
{
  for (int i=0; i<size-sizeof(uintptr_t); i++) {
    if(memcmp(buffer+i,&ptr,sizeof(ptr))==0){
      uintptr_t key_addr = offset+i;
      uintptr_t iv_addr = key_addr - 0x50;
      return iv_addr;
    }
  }
  return 0;
}

memory_map_list_t *init_memory_map_list(size_t capacity)
{
  memory_map_list_t *mmlist=malloc(sizeof(*mmlist));
  mmlist->maps =malloc(capacity*sizeof(memory_map_t));
  mmlist->count=0;
  mmlist->capacity = capacity;
  return mmlist;
}

key_list_t *init_key_list(size_t capacity)
{
  key_list_t *list=malloc(sizeof(*list));
  list->keys =malloc(capacity*sizeof(aes_128_key_t));
  list->count=0;
  list->capacity = capacity;
  return list;
}

void add_aes_128_key(key_list_t *list,aes_128_key_t *key)
{
  if(list->count>=list->capacity){
    list->capacity*=2;
    list->keys=realloc(list->keys,list->capacity*sizeof(aes_128_key_t));
  }
  memcpy(&list->keys[list->count++],key,sizeof(aes_128_key_t));
  free(key);
}

void add_memory_map(memory_map_list_t *list,uintptr_t start,uintptr_t end,char perms[5])
{
  if(list->count>=list->capacity){
    list->capacity*=2;
    list->maps=realloc(list->maps,list->capacity*sizeof(memory_map_t));
  }
  memory_map_t *map=&list->maps[list->count++];
  map->start_addr =start;
  map->end_addr =end;
  memcpy(map->perms,perms,5); 
}

memory_map_list_t* parse_memory_maps(int pid)
{
  memory_map_list_t *maps =init_memory_map_list(100);
  char maps_file[64] = {0};
  sprintf(maps_file, "/proc/%ld/maps",(long)pid);
  FILE *maps_file_ptr =fopen(maps_file,"r");
  if (maps_file_ptr == NULL) {
    perror("fopen");
    return NULL;
  }
  int buf_len=255;
  char buffer[buf_len];
  while(fgets(buffer,buf_len,maps_file_ptr)) {
    uintptr_t start;
    uintptr_t end;
    char perms[5]={0};
    sscanf(buffer,"%lx-%lx %s\n",&start,&end,perms);
    if (strstr(perms,"rw")!=NULL){
      add_memory_map(maps,start,end,perms);
    }
  }
  fclose(maps_file_ptr);
  return maps;
}

int open_memory(int pid)
{
  char mem_file[64] = {0};
  sprintf(mem_file, "/proc/%ld/mem",(long)pid);
  int mem_fd =open(mem_file,O_RDONLY);
  if(mem_fd==-1) {
    perror("open");
    return EXIT_FAILURE;
  }
  return mem_fd;
}

void scan_aes_keys(int mem_fd,memory_map_list_t *maps,key_list_t *keylist)
{
  for(int i=0; i<maps->count;i++) {
    memory_map_t map =maps->maps[i];
    char buf[BUFFER_SIZE];
    unsigned long offset = map.start_addr;
    while(offset < map.end_addr-BUFFER_SIZE) {
      read_offset(mem_fd,buf,sizeof(buf),offset);
      printf("segment start=%lx,end=%lx\n",map.start_addr,map.end_addr);
      printf("remeaning bytes=%lu\n",map.end_addr-offset);
      printf("lseek offset address=%lx\n",offset);
      aes_128_key_t* aes_key = find_aes_128_keys(buf,BUFFER_SIZE,offset);
      if (aes_key) {
	print_key(aes_key);
	add_aes_128_key(keylist,aes_key);
      }
      offset+=BUFFER_SIZE;
    }
  }
}

ssize_t read_offset(int fd,void *buf,size_t count,off_t offset)
{
  int seek_result = lseek(fd,offset,SEEK_SET);
  if (seek_result == -1) {
    perror("lseek");
    return 0;
  }
  int read_result = read(fd,buf,count);
  return read_result;
}

void scan_iv_keys(int mem_fd,memory_map_list_t *maps,key_list_t *keylist)
{
  for(int i=0; i<maps->count;i++) {
    memory_map_t map =maps->maps[i];
    for(int j=0; j<keylist->count;j++) {
      aes_128_key_t key=keylist->keys[j];
      printf("finding pointers for key[%d]=%lx in memory map[%d]\n",j,key.address,i);
      char buf[BUFFER_SIZE];
      unsigned long offset = map.start_addr;
      while(offset < map.end_addr-BUFFER_SIZE) {
	read_offset(mem_fd,buf,sizeof(buf),offset);
        uintptr_t iv_addr = find_iv_addr(buf,BUFFER_SIZE,keylist->keys[j].address,offset);
        if (iv_addr>0) {
          printf("iv address=%lx\n",iv_addr);
          uint8_t iv[16]={0};
	  read_offset(mem_fd,iv,sizeof(iv),iv_addr);
	  print_key(&key);
          printf("iv=");
          print_hex(iv,16);
	  //https://github.com/openssl/openssl/blob/399781ef788b95eb376ecad0427f91cdbdc052bc/include/openssl/obj_mac.h#L3245
	  //https://github.com/openssl/openssl/blob/b372b1f76450acdfed1e2301a39810146e28b02c/crypto/evp/evp_local.h#L24
	  //https://github.com/openssl/openssl/blob/b372b1f76450acdfed1e2301a39810146e28b02c/include/crypto/evp.h#L131
	  uintptr_t evp_cipher_st_ptr =0;
	  int nid=0;
	  int block_size=0;
	  int key_len=0;
	  int iv_len=0;
	  read_offset(mem_fd,&evp_cipher_st_ptr,sizeof(evp_cipher_st_ptr),iv_addr-0x28);
	  read_offset(mem_fd,&nid,sizeof(nid),evp_cipher_st_ptr);
	  read_offset(mem_fd,&block_size,sizeof(block_size),evp_cipher_st_ptr+4);
	  read_offset(mem_fd,&key_len,sizeof(key_len),evp_cipher_st_ptr+8);
	  read_offset(mem_fd,&iv_len,sizeof(iv_len),evp_cipher_st_ptr+12);
          printf("nid=%d\n",nid);
          printf("block_size=%d\n",block_size);
          printf("key_len=%d\n",key_len);
          printf("iv_len=%d\n",iv_len);
        }
        offset+=BUFFER_SIZE;
      }
    }
  }
}
