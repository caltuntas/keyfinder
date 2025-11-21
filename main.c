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
  scan_aes_keys(mem_fd,maps,keylist);
  scan_iv_keys(mem_fd,maps,keylist);

  if(close(mem_fd)==-1) {
    perror("close");
    return EXIT_FAILURE;
  }

  ptrace(PTRACE_DETACH,pid,NULL,NULL);

  return EXIT_SUCCESS;
}
