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

void print_hex(unsigned char *buf,size_t s) 
{
  for (int i=0; i<s; i++) {
    printf("%02x,",buf[i]);
  }
  printf("\n");
}

//TODO:what if key starts at the end of current buffer and goes beyond the next?
key_search_result_t check_aes_128_key_expantion(uint8_t *buffer,size_t size,uintptr_t base_addr) 
{
  key_search_result_t res = {false,0,0,{0}};
  uint8_t all_keys[176]={0};
  uint8_t first_key[16]={0};
  for (int i=0; i<size-175; i++) {
    //printf("buffer window=%d\n",i);
    uint8_t expanded_key[16]={0};
    memcpy(first_key,buffer+i,16);
    //printf("candidate key=");
    //print_hex(first_key,16);
    memset(all_keys,0,176);
    memcpy(all_keys,first_key,16);
    memcpy(expanded_key,first_key,16);
    for (int round=1; round<11; round++) {
      expand_key(round,expanded_key);
      //printf("expanded key=");
      //print_hex(expanded_key,16);
      memcpy(all_keys+(round*16),expanded_key,16);
      //printf("all keys=");
      //print_hex(all_keys,16*(round+1));
      if(memcmp(buffer+i,all_keys,round*16+16)!=0)
        break;
      if (round==10) {
        res.found =true;
        res.offset=i;
        res.address = base_addr+i;
        memcpy(res.key,first_key,16); 
        return res;
      }
    }
  }
  return res;
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

void add_memory_map(memory_map_list_t *list,uintptr_t start,uintptr_t end,char perms[5])
{
  if(list->count>=list->capacity){
    list->capacity*=2;
    list->maps=realloc(list->maps,list->capacity*sizeof(memory_map_t));
  }
  memory_map_t *map=malloc(sizeof(*map));
  map->start_addr =start;
  map->end_addr =end;
  memcpy(map->perms,perms,5); 
  list->maps[list->count++]=*map;
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
