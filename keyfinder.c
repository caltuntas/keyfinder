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

void convert_uint64_to_bytes(uint64_t w,uint8_t arr[8]) {
  arr[0] = w >> 56;
  arr[1] = w >> 48;
  arr[2] = w >> 40;
  arr[3] = w >> 32;
  arr[4] = w >> 24;
  arr[5] = w >> 16;
  arr[6] = w >> 8;
  arr[7] = w >> 0;
}

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
