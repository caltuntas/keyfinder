#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>


int main()
{
  int pid=323339;
  char file[64] = {0};
  sprintf(file, "/proc/%ld/mem",(long)pid);
  printf("file name is %s",file);

  long ptrace_res = ptrace(PTRACE_ATTACH,pid,NULL,NULL);
  if(ptrace_res==-1) {
    perror("ptrace");
    return EXIT_FAILURE;
  }
  waitpid(pid,NULL,0);

  int fd =open(file,O_RDONLY);
  if(fd==-1) {
    perror("open");
    return EXIT_FAILURE;
  }

  char buf[1024];
  unsigned long offset = 0x55b3e9024000UL;
  int seek_result = lseek(fd,offset,SEEK_SET);
  if (seek_result == -1) {
    perror("lseek");
    return EXIT_FAILURE;
  }

  int read_result = read(fd,buf,sizeof(buf));

  if(read_result==-1) {
    perror("read");
    return EXIT_FAILURE;
  }

  if(close(fd)==-1) {
    perror("close");
    return EXIT_FAILURE;
  }

  ptrace(PTRACE_DETACH,pid,NULL,NULL);

  return EXIT_SUCCESS;
}
