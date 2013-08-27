#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "info_list.h"
#include "eth_reader.h"

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

pcap_t *phandle = NULL;
char dev_name[MAX_DEV_NAME_LEN+1] = {0};

void callback(u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  int i;
  int eth_header_len;
  if(packet==NULL)
  {
    fprintf(stdout,"empty packet\n");
    return;
  }
  // hexdump(packet,100);
  // printf("data-link %d\n",*user);
  switch (*user) {
    case DLT_NULL:
      eth_header_len = 4;
      break;
    case DLT_EN10MB:
      eth_header_len = 14;
      break;
    case DLT_SLIP:
      eth_header_len = 24;
      break;
    case DLT_PPP:
      eth_header_len = 5;
      break;
    case DLT_LINUX_SLL:
      eth_header_len = 16;
      break;
    default:
      eth_header_len = 14;
      break;
  }

  connection_info_t info;
  u_char *p,*ipheader;
  ipheader = (char *)packet + eth_header_len;

  p = ipheader + IPPORT_OFFSET;
  memcpy((char *)&info.src_port,p,2);
  memcpy((char *)&info.dst_port,p+2,2);
  info.src_port = ntohs(info.src_port);
  info.dst_port = ntohs(info.dst_port);

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

int choose_and_open()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  char buf[10];
  if (pcap_findalldevs(&alldevs, errbuf) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    return -1;
  }
  int i = 0;
  pcap_if_t *d;
  for(d = alldevs; d != NULL; d = d->next)
  {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n\n");
  }

  printf("Pls choose a device:\n");
  if(fgets(buf,9,stdin) == NULL)return -1;
  int ch = atoi(buf);
  for(i = 0, d = alldevs; d != NULL; d = d->next)
  {
    i++;
    if(i == ch)
    {
      phandle = pcap_open_live(d->name,BUFSIZ,0,1,errbuf);
      break;
    }
  }

  pcap_freealldevs(alldevs);
  return 0;
}

int init_eth_reader()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  if(PORT > 65535 || PORT < 0)return -1;
#ifdef _CLIENT_
  char filter_exp[50]={0};
  sprintf(filter_exp,"tcp src port %d and tcp[13] == 0x12",PORT);
#else
  char filter_exp[50]={0};
  sprintf(filter_exp,"tcp dst port %d and tcp[13] == 2",PORT);
#endif

  if(strlen(dev_name) != 0)
    phandle = pcap_open_live(dev_name,BUFSIZ,0,1,errbuf);

  if(phandle == NULL)
  {
    phandle = pcap_open_live("any",BUFSIZ,0,1,errbuf);
    if(phandle == NULL) //open dev failed,choose one.
    {
      if(choose_and_open())
        return -1;
    }
  }
  
  if(phandle == NULL) return -1;

  if(pcap_compile(phandle,&fp,filter_exp,1,PCAP_NETMASK_UNKNOWN) == -1)
  {
    fprintf(stderr,"parse filter failed %s:%s\n",filter_exp,pcap_geterr((pcap_t*)errbuf));
    return -1;
  }

  if(pcap_setfilter(phandle,&fp) == -1)
  {
    fprintf(stderr,"install filter failed %s\n",filter_exp);
    return -1;
  }

  return 0;
}


//int main()
void* eth_reader(void* arg)
{
  u_char datalink;
  datalink = pcap_datalink(phandle);
  pcap_loop(phandle,0,callback,&datalink);
  
  pcap_close(phandle);
}

