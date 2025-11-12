#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "process.h"

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
