#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <sys/ioctl.h>
#include <linux/filter.h>

#include "eth_reader.h"

//to do:use libpcap

extern pthread_mutex_t info_mutex;
char reader_ready = 0;
int sock;

void print_tcp_info(connection_info_t* info)
{
  fprintf(stderr,"src:%d.%d.%d.%d:%d    ",info->src_addr[0],
    info->src_addr[1],info->src_addr[2],info->src_addr[2],info->src_port);
  fprintf(stderr,"dst:%d.%d.%d.%d:%d\n",info->dst_addr[0],
    info->src_addr[1],info->dst_addr[2],info->dst_addr[2],info->dst_port);
  fprintf(stderr,"    seq:%u\n",info->seq);
  return;
}

int init_eth_reader()
{
  if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
  {
    fprintf(stderr, "create socket error\n");
    close(sock);
    return -1;
  }
  return 0;
}


void* eth_reader(void* arg)
{
  fd_set rfds;
  init_eth_reader();
  connection_info_t *info = (connection_info_t *)arg;
  unsigned char *p,*ipheader;
  int len;
  unsigned int sequence;
  unsigned char buffer[ETH_FRAME_TOTALLEN];
  int eth_header_len = ETH_HEADER_LEN;

  reader_ready = 1;

  while(1) 
  {
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    int ret = select(sock+1, &rfds, NULL, NULL, NULL);
    if(ret == 0) continue;
    if(FD_ISSET(sock, &rfds) == 0)
      continue;
    len = recvfrom(sock, buffer, ETH_FRAME_TOTALLEN, 0, NULL, NULL);
    if(len < 42 || len > 100) // packet too small or too large
    {
      continue;
    }

    if(buffer[12] != 0x08 || buffer[13] != 0) // Linux cooked capture
      eth_header_len = 0;

    if((buffer + eth_header_len + IPPROTO_OFFSET)[0] != IPPROTO_TCP) //not TCP
    {
      continue;
    }
    
    ipheader = buffer + eth_header_len;

    p = ipheader + IPPORT_OFFSET;
    memcpy((char *)&info->src_port,p,2);
    memcpy((char *)&info->dst_port,p+2,2);
    info->src_port = ntohs(info->src_port);
    info->dst_port = ntohs(info->dst_port);
#ifdef _CLIENT_
    if(info->src_port != PORT)continue;      //clinet src port //server dst port
#else
    if(info->dst_port != PORT)continue;  
#endif

    p = ipheader + IPFLAG_OFFSET;

#ifdef _CLIENT_
    if((p[0]&0X03) != 0 || p[1] != 0x12) //SYN
    {
      continue;
    }
    p = ipheader + IPSEQ_OFFSET2;
    memcpy((char *)&info->seq,p,4);
    info->seq = ntohl(info->seq);
#else
    if((p[0]&0X03) != 0 || p[1] != 2) //SYN
    {
      continue;
    }
    p = ipheader + IPSEQ_OFFSET;
    memcpy((char *)&info->seq,p,4);
    info->seq = ntohl(info->seq);
    info->seq += 1;
#endif


    p = ipheader + IPADDR_OFFSET;
    memcpy(info->src_addr,p,4);
    memcpy(info->dst_addr,p+4,4);
  }
}
