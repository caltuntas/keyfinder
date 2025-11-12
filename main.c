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
#include "process.h"


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

  size_t len=0;
  memory_map_t *maps =parse_memory_maps(pid,&len);
  key_search_result_t keys[10]={0};

  int key_count=0;
  for(int i=0; i<len;i++) {
    if (strstr(maps[i].perms,"rw")!=NULL){
      char buf[BUFFER_SIZE];
      unsigned long offset = maps[i].start_addr;
      while(offset < maps[i].end_addr-BUFFER_SIZE) {
	int seek_result = lseek(mem_fd,offset,SEEK_SET);
	if (seek_result == -1) {
	  perror("lseek");
	  return EXIT_FAILURE;
	}

	int read_result = read(mem_fd,buf,sizeof(buf));
	printf("segment start=%lx,end=%lx\n",maps[i].start_addr,maps[i].end_addr);
	printf("remeaning bytes=%lu\n",maps[i].end_addr-offset);
	printf("lseek offset address=%lx\n",offset);
	key_search_result_t is_aes_128 = check_aes_128_key_expantion(buf,BUFFER_SIZE,offset);
	if (is_aes_128.found) {
	printf("bytes read from memory=%d\n",read_result);
	print_hex(buf,read_result);
	printf("--------\n");
	  printf("aes block is found\n");
	  printf("offset in block=%d\n",is_aes_128.offset);
	  //uintptr_t key_addr = offset+is_aes_128.offset;
	  //void *key_ptr = (void*)key_addr;
	  //uintptr_t iv_addr = key_addr - 0x50;
	  printf("key address=%lx\n",is_aes_128.address);
	  //printf("iv address=%lx\n",iv_addr);
	  printf("key=");
	  print_hex(is_aes_128.key,16);
	  keys[key_count]=is_aes_128;
	  key_count++;

	  //return EXIT_SUCCESS;
	}

	offset+=BUFFER_SIZE;

	if(read_result==-1) {
	  perror("read");
	  return EXIT_FAILURE;
	}
      }
    }
  }

  for(int i=0; i<len;i++) {
    if (strstr(maps[i].perms,"rw")!=NULL){
      for(int j=0; j<key_count;j++) {
	printf("finding pointers for key[%d]=%lx in memory map[%d]\n",j,keys[j].address,i);
	char buf[BUFFER_SIZE];
	unsigned long offset = maps[i].start_addr;
	while(offset < maps[i].end_addr-BUFFER_SIZE) {
	  int seek_result = lseek(mem_fd,offset,SEEK_SET);
	  if (seek_result == -1) {
	    perror("lseek");
	    return EXIT_FAILURE;
	  }

	  int read_result = read(mem_fd,buf,sizeof(buf));
	  int os = find_pointer(buf,BUFFER_SIZE,keys[j].address);
	  if (os>=0) {
	    printf("start address=%lx,found offset=%d\n",maps[i].start_addr,os);
	    printf("pointers for key[%d]=%lx\n",j,offset+os);
	  }
	  offset+=BUFFER_SIZE;
	}

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
