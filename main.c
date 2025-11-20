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


//TODO:graceful exit and resource clean-up
int main(int argc, char **argv)
{
  char *str_pid = argv[1];
  int pid=strtol(str_pid,NULL,10);

  long ptrace_res = ptrace(PTRACE_ATTACH,pid,NULL,NULL);
  if(ptrace_res==-1) {
    perror("ptrace");
    return EXIT_FAILURE;
  }
  waitpid(pid,NULL,0);

  memory_map_list_t *maps =parse_memory_maps(pid);
  key_list_t *keylist=init_key_list(10);

  int mem_fd=open_memory(pid);
  scan_memory(mem_fd,maps,keylist);
  for(int i=0; i<maps->count;i++) {
    memory_map_t map =maps->maps[i];
    for(int j=0; j<keylist->count;j++) {
      printf("finding pointers for key[%d]=%lx in memory map[%d]\n",j,keylist->keys[j].address,i);
      char buf[BUFFER_SIZE];
      unsigned long offset = map.start_addr;
      while(offset < map.end_addr-BUFFER_SIZE) {
	read_offset(mem_fd,buf,sizeof(buf),offset);
        uintptr_t iv_addr = find_iv_addr(buf,BUFFER_SIZE,keylist->keys[j].address,offset);
        if (iv_addr>0) {
          printf("iv address=%lx\n",iv_addr);
          uint8_t iv[16]={0};
	  read_offset(mem_fd,iv,sizeof(iv),iv_addr);
          printf("iv value=");
          print_hex(iv,16);
        }
        offset+=BUFFER_SIZE;
      }

    }
  }


  if(close(mem_fd)==-1) {
    perror("close");
    return EXIT_FAILURE;
  }

  ptrace(PTRACE_DETACH,pid,NULL,NULL);

  return EXIT_SUCCESS;
}
