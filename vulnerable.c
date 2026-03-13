#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

char buf[100]; /* Example-only buffer, you'd replace it with other global or
                    local variables appropriate for your use case. */


/* Main entry point. */

int main(int argc, char** argv) {

 
  
  
    /* STEP 1: Fully re-initialize all critical variables. In our example, this
               involves zeroing buf[], our input buffer. */

    memset(buf, 0, 100);

    /* STEP 2: Read input data. When reading from stdin, no special preparation
               is required. When reading from a named file, you need to close
               the old descriptor and reopen the file first!

               Beware of reading from buffered FILE* objects such as stdin. Use
               raw file descriptors or call fopen() / fdopen() in every pass. */

    read(0, buf, 100);

    /* STEP 3: This is where we'd call the tested library on the read data.
               We just have some trivial inline code that faults on 'foo!'. */

    if (buf[0] == 'f') {
      printf("one\n");
      if (buf[1] == 'o') {
        printf("two\n");
        if (buf[2] == 'o') {
          printf("three\n");
          if (buf[3] == '!') {
            printf("four\n");
            abort();
          }
        }
      }
    }
    
    
    if(!memcmp(buf, "GOOD", 4))
    {
        printf("one\n");
        if(!memcmp(buf+4, "FUZZER", 6)){
            printf("two\n");
            abort();
        }
    }


  /* Once the loop is exited, terminate normally - AFL will restart the process
     when this happens, with a clean slate when it comes to allocated memory,
     leftover file descriptors, etc. */

  return 0;

}