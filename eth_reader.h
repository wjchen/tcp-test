#ifndef _ETH_READER_H
#define _ETH_READER_H

#define ETH_FRAME_TOTALLEN 1500
#define MAX_DEV_NAME_LEN 100


#define ETH_HEADER_LEN 14
#define IP_HEADER_LEN  20
#define TCP_HEADER_LEN 40

#define IPPROTO_OFFSET 9
#define IPADDR_OFFSET 12
#define IPPORT_OFFSET 20
#define IPSEQ_OFFSET  24
#define IPSEQ_OFFSET2 28
#define IPFLAG_OFFSET 32

#define PORT 32000

extern char dev_name[MAX_DEV_NAME_LEN+1];

extern void* eth_reader(void* arg);
int init_eth_reader();

#endif