#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rc4.h"


int main(int argc, char *argv[]) {
  u_char key[512];
  u_char input[512];
  u_char output[512];
  int input_len = 512;
  
  strncpy((char *) key, "test11", 256);
  bzero(output,512);
  int j;
  for(j=0; j<512; j++)
  {
    input[j] = j;
  }
  struct rc4_state S_box;
  rc4_init(&S_box,key,strlen(key));
  rc4_crypt(S_box,input,output,512);
  int i = 0;
  printf("\n\n--- Encryption nOutput---:\n");
  for(i=0; i<input_len; i++)
    printf("0%x ", output[i]);
  printf("\n");
  
  rc4_crypt(S_box,output,output,512);
  printf("\n\n--- Decryption Output:\n");
  for(i=0; i<input_len; i++)
    printf("0%x ", output[i]);
  
  rc4_crypt(S_box,output,output,510);
  printf("\n\n--- Decryption Output:\n");
  for(i=0; i<input_len; i++)
    printf("0%x ", output[i]);
  
  rc4_crypt(S_box,output,output,510);
  printf("\n\n--- Decryption Output:\n");
  for(i=0; i<input_len; i++)
    printf("0%x ", output[i]);
  return 0;
}