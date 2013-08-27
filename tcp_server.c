#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "eth_reader.h"
#include "key_gen.h"
#include "info_list.h"
#include "timer.h"
#include "rc4.h"

pthread_t thread_eth_reader;
unsigned short src_port;
unsigned char src_addr[4];
unsigned int seq;

int main(int argc, char**argv)
{
  int listenfd,connfd,n;
  struct sockaddr_in servaddr,cliaddr;
  socklen_t clilen;
  pid_t     childpid;
  char mesg[1000];
  
  if(argc >= 2 && strlen(argv[1]) <= MAX_DEV_NAME_LEN)
    strncpy(dev_name,argv[1],strlen(argv[1]));
  
  if(init_eth_reader())
  {
    fprintf(stderr,"eth reader init failed\n");
    return -1;
  }

  start_timer();
  pthread_create(&thread_eth_reader, NULL, &eth_reader, NULL);

  listenfd=socket(AF_INET,SOCK_STREAM,0);
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(PORT);
  bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

  listen(listenfd,1024);

  while(1)
  {
    clilen=sizeof(cliaddr);
    connfd = accept(listenfd,(struct sockaddr *)&cliaddr,&clilen);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);   
    getpeername(connfd, (struct sockaddr *)&addr, &addr_len);
    src_port = ntohs(addr.sin_port);
    memcpy(src_addr,(char *)&addr.sin_addr,4);
    unsigned int seq = get_tcp_info(src_addr,src_port);
    int count = 0;
    while(seq == 0)
    {
      count++;
      if(count > 3) //something wrong
      {
        close(listenfd);
        return -1;
      }
      seq = get_tcp_info(src_addr,src_port);
    }
    char *key = "a tcp test";
    unsigned char key_new[16]={0};
    struct rc4_state S_box, state;
    
    if(key_gen(key,key_new,seq) < 0)
      return -1;
    rc4_init(&S_box,key_new,16);

    if ((childpid = fork()) == 0)
    {
      close(listenfd);
      while(1)
      {
        n = recvfrom(connfd,mesg,1000,0,(struct sockaddr *)&cliaddr,&clilen);
        if(n<=0){close(listenfd);return -1;}
        rc4_crypt(S_box,mesg,mesg,n);
        mesg[n]=0;
        printf("Received Message:\n");
        printf("%s",mesg);
        printf("-------------------------------------\n");
        rc4_crypt(S_box,mesg,mesg,n);
        sendto(connfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
      }
    }
    close(connfd);
  }
}
