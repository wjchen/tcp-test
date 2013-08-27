#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "version.h"

int key_gen(char *key,unsigned char out[16],unsigned int salt)
{
  MD5_CTX ctx;
  MD5_Init(&ctx);
  //int len = strlen(key);
  //unsigned char data[len+40];
  unsigned char *data = (unsigned char *)malloc(strlen(key)+40);
  sprintf(data,"%u14%saI%s",salt,_VERSION_H,key);
  MD5_Update(&ctx, (void *)data, strlen(data));
  free(data);
  MD5_Final(out,&ctx);
  
  return 0;
}