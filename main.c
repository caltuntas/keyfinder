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


void print_hex(unsigned char *buf,size_t s) 
{
  for (int i=0; i<s; i++) {
    printf("%02x,",buf[i]);
  }
  printf("\n");
}

//TODO:graceful exit and resource clean-up
int main()
{
  int pid=323339;
  char mem_file[64] = {0};
  char maps_file[64] = {0};
  sprintf(mem_file, "/proc/%ld/mem",(long)pid);
  sprintf(maps_file, "/proc/%ld/maps",(long)pid);
  printf("mem_file name is %s",mem_file);
  printf("maps_file name is %s",maps_file);

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

  FILE *maps_file_ptr =fopen(maps_file,"r");
  if (maps_file_ptr == NULL) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  int buf_len=255;
  char buffer[buf_len];
  while(fgets(buffer,buf_len,maps_file_ptr)) {
    unsigned long start_addr;
    unsigned long end_addr;
    char perms[5]={0};
    sscanf(buffer,"%lx-%lx %s\n",&start_addr,&end_addr,perms);
    //printf("start=%lu,end=%lu,perms=%s\n",start_addr,end_addr,perms);

    if (strstr(perms,"rw")!=NULL){
      printf("line---%s\n",buffer);
      //printf("read write section---");
      char buf[BUFFER_SIZE];
      unsigned long offset = start_addr;
      while(offset < end_addr-BUFFER_SIZE) {
	int seek_result = lseek(mem_fd,offset,SEEK_SET);
	if (seek_result == -1) {
	  perror("lseek");
	  return EXIT_FAILURE;
	}

	int read_result = read(mem_fd,buf,sizeof(buf));
	printf("segment start=%x,end=%x\n",start_addr,end_addr);
	printf("remeaning bytes=%lu\n",end_addr-offset);
	printf("lseek offset address=%x\n",offset);
	printf("bytes read from memory=%d\n",read_result);
	print_hex(buf,read_result);
	printf("--------\n");
	bool is_aes_128 = check_aes_128_key_expantion(buf,BUFFER_SIZE);
	if (is_aes_128) {
	  printf("aes block is found\n");
	}else {
	  offset+=BUFFER_SIZE;
	}

	if(read_result==-1) {
	  perror("read");
	  return EXIT_FAILURE;
	}
      }
    }
  }

  fclose(maps_file_ptr);


  if(close(mem_fd)==-1) {
    perror("close");
    return EXIT_FAILURE;
  }

  ptrace(PTRACE_DETACH,pid,NULL,NULL);

  return EXIT_SUCCESS;
}
