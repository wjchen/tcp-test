#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/filter.h>
#include <netpacket/packet.h>

#include "eth_reader.h"
#include "info_list.h"

char dev_name[MAX_DEV_NAME_LEN+1] = {0};
int sock;

int init_eth_reader()
{
  init_tcp_info();
  if((sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
  {
    fprintf(stderr, "create socket error\n");
    close(sock);
    return -1;
  }

//tcpdump -i any -dd tcp dst port 32000  and tcp[13] == 2
//0x28 ldh   load 2 Byte.
//0x30 ldb   load 1 byte.
//0x15 jeq
#ifdef _CLIENT_
  struct sock_filter BPF_code[]= {
    { 0x30, 0, 0, IPPROTO_OFFSET },
    { 0x15, 0, 5, IPPROTO_TCP },
    { 0x28, 0, 0, 0x14 },  //src port offset
    { 0x15, 0, 3, PORT }, //src port
    { 0x30, 0, 0, 0x21 }, //TCP FLAGS OFFSET
    { 0x15, 0, 1, 0x12 }, //TCY SYN ACK
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 }
  };
#else
  struct sock_filter BPF_code[]= {
    { 0x30, 0, 0, IPPROTO_OFFSET },
    { 0x15, 0, 5, IPPROTO_TCP },
    { 0x28, 0, 0, 0x16 },  //dst port offset
    { 0x15, 0, 3, PORT }, //dst port
    { 0x30, 0, 0, 0x21 }, //TCP FLAGS OFFSET
    { 0x15, 0, 1, 2 }, //TCY SYN
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 }
  };
#endif
  struct sock_fprog Filter; 
    
  Filter.len = 8;
  Filter.filter = BPF_code;

  if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, 
                &Filter, sizeof(Filter))<0){
    perror("setsockopt");
    close(sock);
    return -1;
  }

  return 0;
}

//void main()
void* eth_reader(void* arg)
{
  fd_set rfds;
  connection_info_t info;
  unsigned char *p,*ipheader;
  int len;
  unsigned int sequence;
  unsigned char buffer[ETH_FRAME_TOTALLEN];
  int eth_header_len = ETH_HEADER_LEN;

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

    ipheader = buffer;

    p = ipheader + IPPORT_OFFSET;
    memcpy((char *)&info.src_port,p,2);
    memcpy((char *)&info.dst_port,p+2,2);
    info.src_port = ntohs(info.src_port);
    info.dst_port = ntohs(info.dst_port);

    p = ipheader + IPFLAG_OFFSET;

#ifdef _CLIENT_
    p = ipheader + IPSEQ_OFFSET2;
    memcpy((char *)&info.seq,p,4);
    info.seq = ntohl(info.seq);
#else
    p = ipheader + IPSEQ_OFFSET;
    memcpy((char *)&info.seq,p,4);
    info.seq = ntohl(info.seq);
    info.seq += 1;
#endif

    p = ipheader + IPADDR_OFFSET;
    memcpy(info.src_addr,p,4);
    memcpy(info.dst_addr,p+4,4);
    //print_tcp_info(&info);
    if(push_tcp_info(info) == -1)
    {
      fprintf(stderr,"push tcp info failed\n");
    }
  }
}
