#!/bin/bash

# variables
FILE=~/ghosttest.c
OUT_FILE=ghostcheck
need_patch=0

# write c program to file
cat > $FILE <<EOL
/* GHOST vulnerability tester */
/* Credit: http://www.openwall.com/lists/oss-security/2015/01/27/9 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CANARY "in_the_coal_mine"

struct {
  char buffer[1024];
  char canary[sizeof(CANARY)];
} temp = { "buffer", CANARY };

int main(void) {
  struct hostent resbuf;
  struct hostent *result;
  int herrno;
  int retval;

  /*** strlen (name) = sizeof (*host_addr) - sizeof (*h_addr_ptrs) - 1; ***/
  size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;
  char name[sizeof(temp.buffer)];
  memset(name, '0', len);
  name[len] = '\0';

  retval =  gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);
  
  if (strcmp(temp.canary, CANARY) != 0) {
    puts("vulnerable");
    exit(EXIT_SUCCESS);
  }
  if (retval == ERANGE) {
    puts("not vulnerable");
    exit(EXIT_SUCCESS);
  }
  puts("should not happen");
  exit(EXIT_FAILURE);
}
EOL

# compile will GCC
gcc $FILE -o $OUT_FILE

# capture output of C program into variable
return_val=`./$OUT_FILE`

# check if output is "vulnerable", if you so you need to patch!!!!
if [ "$return_val" == "vulnerable" ]; then
  echo "your system is VULNERABLE!!!! Patch ASAP!"
  need_patch=1
else
  echo "your system is NOT VULNERABLE...so relax!"
fi

# clean up
rm -f $FILE
rm -f $OUT_FILE

# fin
exit $need_patch


