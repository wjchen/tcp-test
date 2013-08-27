#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "eth_reader.h"
#include "key_gen.h"
#include "info_list.h"
#include "version.h"
#include "timer.h"
#include "rc4.h"

pthread_t thread_eth_reader;

unsigned short src_port;
unsigned char src_addr[4];
unsigned int seq;


int main(int argc, char**argv)
{
  int sockfd,n;
  struct sockaddr_in servaddr,cliaddr;

  char sendline[1000];
  char recvline[1000];
  if (argc < 2)
  {
     printf("client %s usage:  client <IP address> [eth name]\n",_VERSION_H);
     return -1;
  }

  if(argc >= 3 && strlen(argv[2]) <= MAX_DEV_NAME_LEN)
    strncpy(dev_name,argv[2],strlen(argv[2]));

  if(init_eth_reader())
  {
    fprintf(stderr,"eth reader init failed\n");
    return -1;
  }
  start_timer();
  pthread_create(&thread_eth_reader, NULL, &eth_reader, NULL);
  
  sockfd=socket(AF_INET,SOCK_STREAM,0);
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=inet_addr(argv[1]);
  servaddr.sin_port=htons(PORT);
  connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);   
  getsockname(sockfd, (struct sockaddr *)&addr, &addr_len);
  src_port = ntohs(addr.sin_port);
  memcpy(src_addr,(char *)&addr.sin_addr,4);
  unsigned int seq = get_tcp_info(src_addr,src_port);
  int count = 0;
  while(seq == 0)
  {
    count++;
    if(count > 3) {
      close(sockfd);
      fprintf(stderr,"read tcp seq failed\n");
      return -1;
    }
    seq = get_tcp_info(src_addr,src_port);
  }
  char *key = "a tcp test";
  struct rc4_state S_box;
  unsigned char key_new[16]={0};
  if(key_gen(key,key_new,seq) < 0)
    return -1;
  rc4_init(&S_box,key_new,16);

  while (fgets(sendline, 1000,stdin) != NULL)
  {
    int len = strlen(sendline);
    rc4_crypt(S_box,sendline,sendline,strlen(sendline));
    sendto(sockfd,sendline,len,0,
           (struct sockaddr *)&servaddr,sizeof(servaddr));
    n = recvfrom(sockfd,recvline,1000,0,NULL,NULL);
    rc4_crypt(S_box,recvline,recvline,n);
    recvline[n] = 0;
    fprintf(stderr,"%s\n",recvline);
  }
}
