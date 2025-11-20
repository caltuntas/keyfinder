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
  char mem_file[64] = {0};
  sprintf(mem_file, "/proc/%ld/mem",(long)pid);
  printf("mem_file name is %s",mem_file);

  long ptrace_res = ptrace(PTRACE_ATTACH,pid,NULL,NULL);
  if(ptrace_res==-1) {
    perror("ptrace");
    return EXIT_FAILURE;
  }
  waitpid(pid,NULL,0);

  int mem_fd =open(mem_file,O_RDONLY);
  if(mem_fd==-1) {
    perror("open");
    return EXIT_FAILURE;
  }

  memory_map_list_t *maps =parse_memory_maps(pid);
  key_list_t *keylist=init_key_list(10);

  for(int i=0; i<maps->count;i++) {
    memory_map_t map =maps->maps[i];
    char buf[BUFFER_SIZE];
    unsigned long offset = map.start_addr;
    while(offset < map.end_addr-BUFFER_SIZE) {
      int seek_result = lseek(mem_fd,offset,SEEK_SET);
      if (seek_result == -1) {
        perror("lseek");
        return EXIT_FAILURE;
      }

      int read_result = read(mem_fd,buf,sizeof(buf));
      printf("segment start=%lx,end=%lx\n",map.start_addr,map.end_addr);
      printf("remeaning bytes=%lu\n",map.end_addr-offset);
      printf("lseek offset address=%lx\n",offset);
      aes_128_key_t* aes_key = find_aes_128_keys(buf,BUFFER_SIZE,offset);
      if (aes_key) {
        printf("bytes read from memory=%d\n",read_result);
        print_hex(buf,read_result);
        printf("--------\n");
        printf("aes block is found\n");
        printf("offset in block=%d\n",aes_key->offset);
        printf("key address=%lx\n",aes_key->address);
        printf("key=");
        print_hex(aes_key->key,16);
	add_aes_128_key(keylist,aes_key);
      }

      offset+=BUFFER_SIZE;

      if(read_result==-1) {
        perror("read");
        return EXIT_FAILURE;
      }
    }
  }

  for(int i=0; i<maps->count;i++) {
    memory_map_t map =maps->maps[i];
    for(int j=0; j<keylist->count;j++) {
      printf("finding pointers for key[%d]=%lx in memory map[%d]\n",j,keylist->keys[j].address,i);
      char buf[BUFFER_SIZE];
      unsigned long offset = map.start_addr;
      while(offset < map.end_addr-BUFFER_SIZE) {
        int seek_result = lseek(mem_fd,offset,SEEK_SET);
        if (seek_result == -1) {
          perror("lseek");
          return EXIT_FAILURE;
        }

        int read_result = read(mem_fd,buf,sizeof(buf));
        int os = find_pointer(buf,BUFFER_SIZE,keylist->keys[j].address);
        if (os>=0) {
          printf("start address=%lx,found offset=%d\n",map.start_addr,os);
          printf("pointers for key[%d]=%lx\n",j,offset+os);
          uintptr_t key_addr = offset+os;
          void *key_ptr = (void*)key_addr;
          uintptr_t iv_addr = key_addr - 0x50;
          printf("iv address=%lx\n",iv_addr);
          seek_result = lseek(mem_fd,iv_addr,SEEK_SET);
          if (seek_result == -1) {
            perror("lseek");
            return EXIT_FAILURE;
          }
          uint8_t iv[16]={0};
          read_result = read(mem_fd,iv,sizeof(iv));
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
