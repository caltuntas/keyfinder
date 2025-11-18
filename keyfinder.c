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

memory_map_t* parse_memory_maps(int pid,size_t * const len)
{
  memory_map_t *maps =calloc(500,sizeof(*maps));
  char maps_file[64] = {0};
  sprintf(maps_file, "/proc/%ld/maps",(long)pid);
  FILE *maps_file_ptr =fopen(maps_file,"r");
  if (maps_file_ptr == NULL) {
    perror("fopen");
    return NULL;
  }

  int buf_len=255;
  char buffer[buf_len];
  size_t counter=0;
  while(fgets(buffer,buf_len,maps_file_ptr)) {
    unsigned long start_addr;
    unsigned long end_addr;
    char perms[5]={0};
    sscanf(buffer,"%lx-%lx %s\n",&start_addr,&end_addr,perms);
    maps[counter].start_addr =start_addr;
    maps[counter].end_addr =end_addr;
    memcpy(maps[counter].perms,perms,5); 
    //printf("start=%lu,end=%lu,perms=%s\n",start_addr,end_addr,perms);
    counter++;
    *len=counter;
   }


  fclose(maps_file_ptr);
  return maps;
}
