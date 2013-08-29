#include <stdio.h>
#include <string.h>
#include "info_list.h"
#include "timer.h"

//mutex needed?
connection_info_t info_list[1024];

void init_tcp_info()
{
  memset(info_list,0,sizeof(info_list));
}

#ifdef _CLIENT_
int push_tcp_info(connection_info_t info)  // client dst port
{
  int start = (info.dst_port % 1024);
  int i = start;
  while (info_list[i].use)
  {
    short diff = curr_time - info_list[i].time;
    if(diff > 10 || diff < 0)
      info_list[i].use = 0;
    i = (i+1) % 1024;
    if(i == start)  //all used
      return -1;
  }

  info_list[i] = info;
  info_list[i].time = curr_time;
  info_list[i].use = 1;

  return 0;
}

unsigned int get_tcp_info(unsigned char *dst_addr,unsigned short dst_port)
{
  int start = (dst_port % 1024);
  int i = start;
  while (1)
  {
    if(info_list[i].use)
    {
      short diff = curr_time - info_list[i].time;
      if((memcmp(info_list[i].dst_addr,dst_addr,4) == 0) && 
         (info_list[i].dst_port == dst_port))
      {
        info_list[i].use = 0;
        return info_list[i].seq;
      }
      else if((diff>10) || (diff<0))
        info_list[i].use = 0;
    }
    i = (i+1)%1024;
    if(i == start)
      return 0;
  }
  return 0;
}

#else
int push_tcp_info(connection_info_t info)  //server src port
{
  int start = (info.src_port % 1024);
  int i = start;
  while (info_list[i].use)
  {
    short diff = curr_time - info_list[i].time;
    if((diff>10) || (diff<0))
      info_list[i].use = 0;
    i = (i+1) % 1024;
    if(i == start)  //all used
      return -1;
  }

  info_list[i] = info;
  info_list[i].time = curr_time;
  info_list[i].use = 1;
  return 0;

}

unsigned int get_tcp_info(unsigned char *src_addr,unsigned short src_port)
{
  int start = (src_port % 1024);
  int i = start;

  while (1)
  {
    if(info_list[i].use)
    {
      short diff = curr_time - info_list[i].time;
      if((memcmp(info_list[i].src_addr,src_addr,4) == 0) && 
         (info_list[i].src_port == src_port))
      {
        info_list[i].use = 0;
        return info_list[i].seq;
      }
      else if((diff>10) || (diff<0))
        info_list[i].use = 0;
    }
    i = (i+1)%1024;
    if(i == start)
      return 0;
  }
  return 0;
}

#endif

void print_tcp_info(connection_info_t *info)
{
  fprintf(stderr,"src:%d.%d.%d.%d:%d    ",info->src_addr[0],
    info->src_addr[1],info->src_addr[2],info->src_addr[2],info->src_port);
  fprintf(stderr,"dst:%d.%d.%d.%d:%d\n",info->dst_addr[0],
    info->src_addr[1],info->dst_addr[2],info->dst_addr[2],info->dst_port);
  fprintf(stderr,"    seq:%u\n",info->seq);
  return;
}
