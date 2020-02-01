
#ifndef _PACKET_H_INCLUDED_
#define _PACKET_H_INCLUDED_

#include <string>

#define BUF_SIZE 65536

#define UDP 17
#define TCP 6
#define ICMP 1

using namespace std;

class Packet {
private:
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	__u32 _src_ip;
	__u32 _dst_ip;
	__u16 _src_port;
	__u16 _dst_port;
	__u8 _ttl;
	int index;

	FILE *log_txt;

	unsigned char buffer[BUF_SIZE];
	int buflen;
	struct ethhdr eth_header;
	struct iphdr ip_header;
	unsigned short ip_hdr_len;

	struct icmphdr icmp_header;
	struct udphdr udp_header;
	struct tcphdr tcp_header;

	unsigned char payload[BUF_SIZE];
	int data_len;
	
	void unpack();

public:
	Packet(FILE *log_file);
	void zero();
	int init(int fd,
		 string si, string di,
		 string se, string de,
		 string sp, string dp,
		 string time_to_live,
		 bool use_tcp, bool rst_probe,
		 string devname, string devind);

	int receive(int fd);
	void send_echo(int, int, int);
	void send_tcp(int, unsigned long, bool);

	void log();
	int get_prot1() { return ntohs(eth_header.h_proto); }
	int get_prot2() { return ip_header.protocol; }
	int get_ICMP_type();
	unsigned short get_echo_id();
	unsigned short get_echo_seq();

	string get_src_ip();
	string get_dst_ip();
	int get_ttl() { return ip_header.ttl; }

	unsigned short get_src_port() { return tcp_header.source; }
	unsigned short get_dst_port() { return tcp_header.dest; }
	
	unsigned int get_tcp_seq();
	unsigned int get_tcp_ack_seq();
	
	bool isSyn();
	bool isAck();
	bool isRst();
};


#endif
