
#include <stdio.h>
#include <string.h>
int main(void){
  const unsigned char s[] = {0x3c, 0x37, 0x3d, 0x40, 0x25, 0x3d, 0x2e, 0x36, 0x36, 0x48, 0x0f, 0x34, 0x3f, 0x4a, 0x42, 0x4a, 0x46, 0x16, 0x47, 0x44, 0x3b};
  char in[128];
  if(!fgets(in, sizeof in, stdin)) return 1;
  size_t n = strcspn(in, "\n");
  if(n != sizeof s) return 2;
  for(size_t i=0;i<sizeof s;i++){
     unsigned char want = (unsigned char)((s[i] - i) ^ 0x5a);
     if((unsigned char)in[i] != want) return (int)(10 + i);
  }
  puts("Correct!");
  return 0;
}
