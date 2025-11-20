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

int find_pointer(uint8_t *buffer,size_t size,uintptr_t ptr)
{
  for (int i=0; i<size-sizeof(uintptr_t); i++) {
    if(memcmp(buffer+i,&ptr,sizeof(ptr))==0)
      return i;
  }
  return -1;
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
