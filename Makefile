all:
	gcc -O2 eth_reader_pcap.c tcp_server.c rc4.c key_gen.c info_list.c md5.c timer.c -lpthread -lpcap -o server
	gcc -O2 eth_reader_pcap.c rc4.c tcp_client.c key_gen.c info_list.c md5.c timer.c -lpthread -lpcap -o client

clean:
	rm client server