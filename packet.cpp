#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <fstream>
#include <sstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include <linux/if_packet.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "packet.h"

#define FLAG_USABLE 0x01
#define FLAG_GATEWAY 0x02

using namespace std;

bool mac_equals(unsigned char* a, unsigned char* b) {
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

unsigned short checksum(unsigned short* buff, int _16bitword) {
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
	sum+=htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum>>16);
	return (unsigned short)(~sum);
}

unsigned short checksum2(unsigned short* buff, int _16bitword) {
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
	sum+=*(buff)++;
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum>>16);
	return (unsigned short)(~sum);
}

unsigned short checksum_icmp(unsigned char* buff, int len) {
	len = len - sizeof(struct icmphdr);
	unsigned char *b = (unsigned char*)malloc(sizeof(struct icmphdr) + len);
	memcpy(b, buff, sizeof(struct icmphdr));
	((struct icmphdr*)b)->checksum = 0;
	if (len > 0)
		memcpy(b+sizeof(struct icmphdr), buff+sizeof(icmphdr), len);
	unsigned short res = checksum2((unsigned short*)b, (sizeof(icmphdr) + len) / 2);
	free(b);
	return res;
}

unsigned short checksum_tcp(unsigned char* buff, unsigned short len,
				unsigned int src, unsigned int dst) {
	// For the psuedo header
	unsigned short tcp_seg_len = htons(len);
	unsigned char prot = TCP;

	// Get the length of the data
	int data_len = len - sizeof(struct tcphdr);

	// Create a temporary buffer to store the psuedo header, tcp header, and data
	unsigned char b[BUF_SIZE];
	memset(b, 0, BUF_SIZE);
	
	// Add the psuedo header
	int i = 0;
	memcpy(&b[0], &src, 4);
	memcpy(&b[4], &dst, 4);
	memcpy(&b[9], &prot, 1);
	memcpy(&b[10], &tcp_seg_len, 2);

	// Copy the tcp header
	struct tcphdr *tcp = (struct tcphdr*)(&b[12]);
	memcpy(tcp, buff, sizeof(struct tcphdr));
	tcp->check = 0;

	// Add data
	if (data_len > 0) {
		//cout << "data : ";
		if ((data_len % 2) != 0) {
			data_len++;
		}
		memcpy(tcp+sizeof(struct tcphdr), buff+sizeof(tcphdr), data_len);
	}
	//else
		//cout << "____ : ";

	// Compute the checksum
	unsigned short res = checksum2((unsigned short*)b, (12 + sizeof(tcphdr) + data_len) / 2);
	return res;
}

unsigned short checksum_ip(struct iphdr* buff) {
	struct iphdr temp;
	memcpy(&temp, buff, sizeof(struct iphdr));
	temp.check = 0;
	int mycheck = checksum((unsigned short*)&temp, sizeof(struct iphdr)/2);
}

int str_to_mac(const string &str, unsigned char *buf) {
	memset(buf, 0, 6);
	int res = sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			 &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
	return res;
}

void print_mac(unsigned char *buf) {
	fprintf(stderr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

char *int_to_addr(unsigned int x) {
	struct in_addr addr;
	addr.s_addr = x;//htonl(x);
	return inet_ntoa(addr);
}

int device_index = 0;

Packet::Packet(FILE *log_file) {
	log_txt = log_file;
}

int Packet::init(int fd,
		 string si, string di,
		 string se, string de,
		 string sp, string dp,
		 string time_to_live,
		 bool use_tcp, bool rst_probe,
		 string devname, string devind) {
	//map<string, string> gateway_ips;

	string gateway_str = "0.0.0.0";
	unsigned int gateway_ip = 0;

	_ttl = 64;

	string iface = "none";
	string device = "none";

	fstream route_f("/proc/net/route", fstream::in);
	string line;
	getline(route_f, line);
	while (getline(route_f, line)) {
		stringstream s(line);
		string word;
		vector<string> words;
		while (getline(s, word, '\t'))
			words.push_back(word);
		unsigned int tab_flags = stoi(words[3], NULL, 16);
		unsigned int tab_gateway = stoi(words[2], NULL, 16);
		unsigned int tab_dest = stoi(words[1], NULL, 16);
		unsigned int tab_mask = stoi(words[7], NULL, 16);
		
		/*
		if ((tab_flags & FLAG_GATEWAY) == 0)
			continue;
		if ((tab_flags & FLAG_USABLE) == 0)
			continue;
		*/

		if (tab_dest != 0 || tab_mask != 0)
			continue;

		iface = words[0];
		gateway_ip = tab_gateway;
		gateway_str = int_to_addr(gateway_ip);
		//cout << "IFace: " << iface << endl;
		//cout << "IP: " << gateway_str << endl;
		break;
	}
	route_f.close();

	if (gateway_ip == 0) {
		fprintf(stderr, "Unable to find usable gateway.\nExiting...\n");
		exit(1);
	}

	fstream arp_f("/proc/net/arp", fstream::in);
	getline(arp_f, line);
	while (getline(arp_f, line)) {
		stringstream s(line);
		string word;
		vector<string> words;
		while (getline(s, word, ' ')) {
			if (!word.empty())
				words.push_back(word);
		}
		if (gateway_str.compare(words[0]) == 0) {
			//cout << "MAC: " << words[3] << endl;
			str_to_mac(words[3], dst_mac);
			device = words[5];
			break;
		}
	}
	arp_f.close();

	if (!devname.empty()) {
		device = devname;
		fprintf(stderr, "Using device \'%s\'.\n", device.c_str());
	}

	struct ifreq ifreq_i;
	memset(&ifreq_i,0,sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name,device.c_str(),IFNAMSIZ-1); //giving name of Interface
 
	if((ioctl(fd,SIOCGIFINDEX,&ifreq_i))<0)
		perror("error in index ioctl reading: ");//getting Index Name
 
	//printf("index=%d\n",ifreq_i.ifr_ifindex);
	
	// Get MAC of interface
	struct ifreq ifreq_c;
	memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,device.c_str(),IFNAMSIZ-1);//giving name of Interface
 
	if((ioctl(fd,SIOCGIFHWADDR,&ifreq_c))<0) //getting MAC Address
		perror("error in SIOCGIFHWADDR ioctl reading: ");
	
	// get IP address of the interface
	struct ifreq ifreq_ip;
	memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name,device.c_str(),IFNAMSIZ-1);//giving name of Interface
	if(ioctl(fd,SIOCGIFADDR,&ifreq_ip)<0) //getting IP Address
		perror("error in SIOCGIFADDR: ");
	
	for (int i = 0; i < 6; i++)
		src_mac[i] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[i]);

	memset(&_src_ip, 0, sizeof(_src_ip));
	_src_ip = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
	memset(&_dst_ip, 0, sizeof(_dst_ip));
	_dst_ip = inet_addr(di.c_str());

	device_index = ifreq_i.ifr_ifindex;

	_dst_port = 80;
	_src_port = rand() % 0xffff;

	if (!si.empty()) {
		_src_ip = inet_addr(si.c_str());
		fprintf(stderr, "Using %s as the source IP.\n", int_to_addr(_src_ip));
	}
	if (!se.empty()) {
		str_to_mac(se, src_mac);
		fprintf(stderr, "Using ");
		print_mac(src_mac);
		fprintf(stderr, " as the source MAC.\n");
	}
	if (!de.empty()) {
		str_to_mac(de, dst_mac);
		fprintf(stderr, "Using ");
		print_mac(dst_mac);
		fprintf(stderr, " as the destination MAC.\n");
	}
	if (!sp.empty()) {
		_src_port = stoi(sp, NULL, 10);
		fprintf(stderr, "Using %d as the source port.\n", _src_port);
	}	
	if (!dp.empty()) {
		_dst_port = stoi(dp, NULL, 10);
		fprintf(stderr, "Using %d as the destination port.\n", _dst_port);
	}
	if (!time_to_live.empty()) {
		_ttl = stoi(time_to_live, NULL, 10);
		fprintf(stderr, "TTL set to %d.\n", _ttl);
	}
	if (use_tcp && !rst_probe) {
		fprintf(stderr, "Using TCP syn/ack.\n");
	}
	if (rst_probe) {
		fprintf(stderr, "Using RST probe.\n");
	}

	return 0;
}

void Packet::zero() {
	memset(buffer, 0, BUF_SIZE);
	memset(payload, 0, BUF_SIZE);
	memset(&eth_header, 0, sizeof(struct iphdr));
	memset(&ip_header, 0, sizeof(struct iphdr));
	memset(&icmp_header, 0, sizeof(struct icmphdr));
	memset(&tcp_header, 0, sizeof(struct tcphdr));
	memset(&udp_header, 0, sizeof(struct udphdr));
}

void Packet::unpack() {
	struct ethhdr *eth = (struct ethhdr *)(buffer);\
	// ETH HEADER
	memcpy(&eth_header, eth, sizeof(eth_header));	

	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	memset(&ip_header, 0, sizeof(ip_header));
	
	if (ntohs(eth->h_proto) == ETH_P_IP) {
		memcpy(&ip_header, ip, sizeof(ip_header));
		ip_hdr_len = ip->ihl*4;
	}
		
	
	//ip = (struct iphdr *)( buffer + sizeof(struct ethhdr) );
	/* getting actual size of IP header*/
	
	memset(&icmp_header, 0, sizeof(icmp_header));
	memset(&udp_header, 0, sizeof(udp_header));
	memset(&tcp_header, 0, sizeof(tcp_header));

	int last_hdr_size = 0;
	if ((unsigned int)ip->protocol == UDP) {
		//-----
		/* getting pointer to udp header*/
		struct udphdr *udp=(struct udphdr*)(buffer + ip_hdr_len + sizeof(struct ethhdr));	
		memcpy(&udp_header, udp, sizeof(udp_header));
		last_hdr_size = sizeof(struct udphdr);
	}
	else if ((unsigned int)ip->protocol == TCP) {
		struct tcphdr *tcp=(struct tcphdr*)(buffer + ip_hdr_len + sizeof(struct ethhdr));	
		memcpy(&tcp_header, tcp, sizeof(tcp_header));
		last_hdr_size = sizeof(struct tcphdr);
	}
	else if ((unsigned int)ip->protocol == ICMP) {
		struct icmphdr *icmp=(struct icmphdr*)(buffer + ip_hdr_len + sizeof(struct ethhdr));
		memcpy(&icmp_header, icmp, sizeof(icmp_header));
		last_hdr_size = sizeof(struct icmphdr);
	}
	else {
		//fprintf(log_txt, "\n**UNKNOWN PROTOCOL\n");
	}
		//-----
	unsigned char * data_buf = (buffer + ip_hdr_len + sizeof(struct ethhdr) + last_hdr_size);
	data_len = buflen - (ip_hdr_len + sizeof(struct ethhdr) + last_hdr_size);
		
	memset(payload, 0, BUF_SIZE);
	memcpy(payload, data_buf, data_len);
}

int Packet::receive(int fd) {
	//zero();
	
	struct sockaddr saddr;
	int saddr_len = sizeof (saddr);
 
	//Receive a network packet and copy in to buffer
	buflen=recvfrom(fd,buffer,BUF_SIZE,0,&saddr,(socklen_t *)&saddr_len);
	if(buflen<0)
	{
		//perror("error in reading recvfrom function: ");
		memset(buffer, 0, BUF_SIZE);
		return -1;
	}
	
	unpack();
		log();

	if (mac_equals(eth_header.h_source, src_mac) == false && ip_header.saddr == _dst_ip)
	{
		fprintf(log_txt, "\n> Receiving...\n");
		//cout << buflen << " bytes received from " << get_src_ip() << "\t";
		//log();
		return buflen;
	}
	else if (isRst() && ip_header.daddr == _dst_ip && ip_header.saddr == _src_ip) {
		fprintf(log_txt, "\n> Receiving...\n");
		//cout << buflen << " bytes received from " << get_src_ip() << "\t";
		//log();
		return buflen;
	}
	else {
		return -1;
	}
}

void Packet::send_echo(int fd, int id, int seq) {
	//zero();
	//

	memset(buffer,0,BUF_SIZE);
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	for (int i = 0; i < 6; i++)
		eth->h_source[i] = src_mac[i];

	// filling destination mac. DESTMAC0 to DESTMAC5 are macro having octets of mac address.
	for (int i = 0; i < 6; i++)
		eth->h_dest[i] = dst_mac[i];
	eth->h_proto = htons(ETH_P_IP); //means next header will be IP header

	// end of ethernet header 
	int total_len=sizeof(struct ethhdr);
	
	//IP header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->id = 0;//htons(10201);
	iph->ttl = _ttl;
	iph->protocol = ICMP;
	iph->saddr = _src_ip;
	iph->daddr = _dst_ip;
	iph->check = 0;
	total_len += sizeof(struct iphdr);

	// ICMP Header
	struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
	memset(icmp, 0, sizeof(icmphdr));
	icmp->type = 8;
	icmp->code = 0;
	unsigned short *un = (unsigned short*)&(icmp->un);
	un[0] = id;
	un[1] = seq;
	total_len += sizeof(struct icmphdr);

	//IP length field
	iph->tot_len = htons(total_len - sizeof(struct ethhdr));
	//
	icmp->checksum = checksum_icmp((unsigned char*)icmp, iph->tot_len - sizeof(struct iphdr));
	// IP hdr checksum
	iph->check = ntohs(checksum_ip(iph));
	
	buflen = total_len;
	//Send
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = device_index; // index of interface
	//sadr_ll.sll_ifindex = 2; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
	for (int i = 0; i < 6; i++)
		sadr_ll.sll_addr[i] = dst_mac[i];
	unpack();
	fprintf(log_txt, "\n> Sending...\n");
	log();

	int send_len = sendto(fd,buffer,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
	if(send_len<0) {
		perror("error in sending: ");
		printf("sendlen=%d\nerrno=%d\n",send_len,errno);
		exit(1);
	}
}

void Packet::send_tcp(int fd, unsigned long seqno, bool _ack) {
	memset(buffer,0,BUF_SIZE);
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	for (int i = 0; i < 6; i++)
		eth->h_source[i] = src_mac[i];

	// filling destination mac. DESTMAC0 to DESTMAC5 are macro having octets of mac address.
	for (int i = 0; i < 6; i++)
		eth->h_dest[i] = dst_mac[i];
	eth->h_proto = htons(ETH_P_IP); //means next header will be IP header

	// end of ethernet header 
	int total_len=sizeof(struct ethhdr);
	
	//IP header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->id = 0;//htons(10201);
	iph->ttl = _ttl;
	iph->protocol = TCP;
	iph->saddr = _src_ip;
	iph->daddr = _dst_ip;
	iph->check = 0;
	total_len += sizeof(struct iphdr);

	// TCP Header
	struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
	memset(tcp, 0, sizeof(struct tcphdr));
	tcp->source = htons(_src_port);
	tcp->dest = htons(_dst_port);
	tcp->seq = htonl(seqno);
	tcp->window = 0xffff;
	tcp->doff = 5;
	tcp->syn = 1;
	
	if (_ack)
		tcp->ack = 1;
	
	total_len += sizeof(struct tcphdr);

	//IP length field
	iph->tot_len = htons(total_len - sizeof(struct ethhdr));
	//
	tcp->check = checksum_tcp((unsigned char*)tcp, ntohs(iph->tot_len) - sizeof(struct iphdr), iph->saddr, iph->daddr);
	// IP hdr checksum
	iph->check = ntohs(checksum_ip(iph));
	
	buflen = total_len;
	//Send
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = device_index; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
	for (int i = 0; i < 6; i++)
		sadr_ll.sll_addr[i] = dst_mac[i];
	unpack();
	fprintf(log_txt, "\n> Sending...\n");
	log();

	int send_len = sendto(fd,buffer,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
	if(send_len<0) {
		perror("error in sending: ");
		printf("sendlen=%d\nerrno=%d\n",send_len,errno);
		exit(1);
	}
}

void Packet::log() {
	
	struct ethhdr *eth = &eth_header;
	fprintf(log_txt, "\nEthernet Header\n");
	fprintf(log_txt, "\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
		eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt, "\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
		eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt, "\t|-Protocol : %d\n", ntohs(eth->h_proto));
	//-----
	unsigned short iphdrlen;
	struct sockaddr_in source, dest;
	struct iphdr *ip = &ip_header;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	if (ntohs(eth->h_proto) == ETH_P_IP) {
		fprintf(log_txt, "\nIP Header\n");
		fprintf(log_txt, "\t|-Version : %d\n",(unsigned int)ip->version);
		fprintf(log_txt , "\t|-Internet Header Length : %d DWORDS or %d Bytes\n",
			(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
		fprintf(log_txt , "\t|-Type Of Service : %d\n",(unsigned int)ip->tos);
		fprintf(log_txt , "\t|-Total Length : %d Bytes\n",ntohs(ip->tot_len));

		fprintf(log_txt , "\t|-Identification : %d\n",ntohs(ip->id));
		fprintf(log_txt , "\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
		fprintf(log_txt , "\t|-Protocol : %d\n",(unsigned int)ip->protocol);

		struct iphdr temp;
		memcpy(&temp, buffer + sizeof(struct ethhdr), sizeof(temp));
		temp.check = 0;
		unsigned short mycheck = checksum((unsigned short*)&temp, sizeof(struct iphdr)/2);

		fprintf(log_txt , "\t|-Header Checksum : %d | %d\n",ntohs(ip->check), checksum_ip(ip));
		fprintf(log_txt , "\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
		fprintf(log_txt , "\t|-Destination IP : %s\n",inet_ntoa(dest.sin_addr));
	}
	else {
		fprintf(log_txt, "\n**NOT AN IP HEADER\n");
		return;
	}
	
	//ip = (struct iphdr *)( buffer + sizeof(struct ethhdr) );
	//getting actual size of IP header
	iphdrlen = ip->ihl*4;
	int last_hdr_size = 0;
	if ((unsigned int)ip->protocol == UDP) {
		//-----
		//getting pointer to udp header
		struct udphdr *udp=&udp_header;	
		fprintf(log_txt, "\nUDP Header\n");
		fprintf(log_txt, "\t|-Source Port : %d\n", ntohs(udp->source));
		fprintf(log_txt, "\t|-Destination Port : %d\n", ntohs(udp->dest));
		fprintf(log_txt, "\t|-UDP Length : %d\n", ntohs(udp->len));
		fprintf(log_txt, "\t|-UDP Checksum : %d\n", ntohs(udp->check));	

		last_hdr_size = sizeof(struct udphdr);
	}
	else if ((unsigned int)ip->protocol == TCP) {
		struct tcphdr *tcp = &tcp_header;
		fprintf(log_txt, "\nTCP Header\n");
		fprintf(log_txt, "\t|-Source Port : %d\n", ntohs(tcp->source));
		fprintf(log_txt, "\t|-Destination Port : %d\n", ntohs(tcp->dest));
		fprintf(log_txt, "\t|-Sequence Number : %d\n", ntohs(tcp->seq));
		fprintf(log_txt, "\t|-Ack_Seq : %d\n", ntohs(tcp->ack_seq));
		fprintf(log_txt, "\t|-Window: %d\n", ntohs(tcp->window));

		//printf("seglen = %d\n", ntohs(ip->tot_len) - iphdrlen);
		
		unsigned short mycheck = checksum_tcp((unsigned char*)tcp, ntohs(ip->tot_len) - iphdrlen,
						      ip->saddr, ip->daddr);

		fprintf(log_txt, "\t|-Check: %.4x | %.4x\n", tcp->check, mycheck);
		fprintf(log_txt, "\t|-syn: %d\n", tcp->syn);
		fprintf(log_txt, "\t|-rst: %d\n", tcp->rst);
		fprintf(log_txt, "\t|-ack: %d\n", tcp->ack);
		fprintf(log_txt, "\t|-fin: %d\n", tcp->fin);

		last_hdr_size = sizeof(struct tcphdr);
	}
	else if ((unsigned int)ip->protocol == ICMP) {
		struct icmphdr *icmp=&icmp_header;
		fprintf(log_txt, "\nICMP Header\n");
		fprintf(log_txt, "\t|-Type : %d\n", icmp->type);
		fprintf(log_txt, "\t|-Code : %d\n", icmp->code);
		unsigned short mycheck = checksum_icmp((unsigned char*)icmp, ntohs(ip->tot_len) - iphdrlen);
		fprintf(log_txt, "\t|-Checksum : %d | %d\n", icmp->checksum, mycheck);
		unsigned short *p = (unsigned short*)&(icmp->un);
		fprintf(log_txt, "\t|-Indentifier : %d\n", p[0]);
		fprintf(log_txt, "\t|-Sequence Number : %d\n", p[1]);
		last_hdr_size = sizeof(struct icmphdr);
	}
	else {
		fprintf(log_txt, "\n**UNKNOWN PROTOCOL\n");
	}
	
	//-----
	fprintf(log_txt, "\nData\n");
	unsigned char * data = (buffer + iphdrlen + sizeof(struct ethhdr) + last_hdr_size);
	int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + last_hdr_size);
	for(int i=0;i<remaining_data;i++)
	{
		if(i!=0 && i%16==0)
			fprintf(log_txt,"\n");
		fprintf(log_txt," %.2X ",data[i]);		
	}
	fprintf(log_txt, "\n");
	fprintf(log_txt, "\n==================================================\n");
	
}

int Packet::get_ICMP_type() {
	if (get_prot2() != ICMP)
		return -1;
	return icmp_header.type;
}

unsigned short Packet::get_echo_id() {
	if (get_ICMP_type() < 0)
		return 0;
	unsigned short *p = (unsigned short*)&(icmp_header.un);
	return (p[0]);
}

unsigned short Packet::get_echo_seq() {
	if (get_ICMP_type() < 0) {
		return 0;
	}
	unsigned short *p = (unsigned short*)&(icmp_header.un);
	return (p[1]);
}

string Packet::get_src_ip() {
	string s = int_to_addr(ip_header.saddr);
	return s;
}

string Packet::get_dst_ip() {
	string s = int_to_addr(ip_header.daddr);
	return s;
}

unsigned int Packet::get_tcp_seq() {
	if (get_prot2() != TCP)
		return 0;
	return tcp_header.seq;
}

unsigned int Packet::get_tcp_ack_seq() {
	if (get_prot2() != TCP)
		return 0;
	return tcp_header.ack_seq;
}

bool Packet::isSyn() {
	if (get_prot2() != TCP)
		return false;
	return (tcp_header.syn == 1);
}

bool Packet::isAck() {
	if (get_prot2() != TCP)
		return false;
	return (tcp_header.ack == 1);
}

bool Packet::isRst() {
	if (get_prot2() != TCP)
		return false;
	return (tcp_header.rst == 1);
}




