#ifndef _INFO_LIST_H
#define _INFO_LIST_H

typedef struct connection_info_s
{
  unsigned char src_addr[4];
  unsigned char dst_addr[4];
  unsigned short src_port;
  unsigned short dst_port;
  unsigned int seq;
  unsigned short use;
  short time;
} connection_info_t;

extern int push_tcp_info(connection_info_t);
extern unsigned int get_tcp_info(unsigned char *,unsigned short);


#endif