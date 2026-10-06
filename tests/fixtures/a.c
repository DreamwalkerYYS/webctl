
#include <stdio.h>
#include <string.h>
int main(void){
  const unsigned char enc[] = {0x3c, 0x36, 0x3b, 0x3d, 0x21, 0x28, 0x3f, 0x2c, 0x05, 0x28, 0x35, 0x3e, 0x3b, 0x2e, 0x3b, 0x05, 0x22, 0x35, 0x28, 0x27};
  char in[128];
  if(!fgets(in, sizeof in, stdin)) return 1;
  size_t n = strcspn(in, "\n");
  if(n != sizeof enc) { puts("wrong length"); return 2; }
  for(size_t i=0;i<n;i++) if(((unsigned char)in[i] ^ 0x5a) != enc[i]) { puts("wrong"); return 3; }
  puts("Correct!");
  return 0;
}
