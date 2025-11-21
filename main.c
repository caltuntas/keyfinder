#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "keyfinder.h"

int main(int argc, char **argv)
{
  int mem_fd=-1;
  bool attached=false;
  int ret=EXIT_FAILURE;
  memory_map_list_t *maps=NULL;
  key_list_t *keylist=NULL;

  char *str_pid = argv[1];
  int pid=strtol(str_pid,NULL,10);

  if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1) {
    fprintf(stderr, "ptrace attach pid=%ld, %s\n", pid, strerror(errno));
    goto clean;
  }
  attached=true;

  if(waitpid(pid,NULL,0)==-1){
    fprintf(stderr, "waitpid pid=%ld, %s\n", pid, strerror(errno));
    goto clean;
  }

  maps=parse_memory_maps(pid);
  if(!maps) 
    goto clean;

  keylist=init_key_list(10);
  if(!keylist) 
    goto clean;

  mem_fd=open_memory(pid);
  if(mem_fd<0) 
    goto clean;

  scan_aes_keys(mem_fd,maps,keylist);
  scan_iv_keys(mem_fd,maps,keylist);

  ret=EXIT_SUCCESS;
clean:
  if(maps) 
    free_memory_map_list(maps);

  if(keylist)
    free_key_list(keylist);

  if(mem_fd!=-1) 
    close_memory(mem_fd);

  if(attached)
    ptrace(PTRACE_DETACH,pid,NULL,NULL);

  return ret;
}
