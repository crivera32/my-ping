#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>

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

#include "timestamp.h"
#include "packet.h"

#define TIMEOUT SEC/100
#define EXIT_TIMER SEC*3

using namespace std;

FILE *log_txt;

int recv_socket;
int send_socket;

string source_ip, destination_ip, source_mac, destination_mac, source_port, destination_port,
	time_to_live, device_name, device_ind;

bool use_tcp;
bool rst_probe;

vector<string> args;
unordered_map<int, struct timeval> ts_map;

// Get the command line options from an input string
string get_cmd_option(const string &s) {
	auto p = find(args.begin(), args.end(), s);
	if (p != args.end()) {
		auto next = p;
		++next;
		if (next != args.end())
			return *next;
		return *p;
	}
	return "";
}

// Some initialization
void init() {
	srand(time(NULL));
	
	// First set up the sockets, timeout values, and log file
	recv_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (recv_socket < 0) {
		perror("create socket failed: ");
		exit(1);
	}

	struct timeval t;
	t.tv_sec = 0;
	t.tv_usec = TIMEOUT;

	int res = setsockopt(recv_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
	if (res < 0) {
		perror("set timeout failed: ");
		exit(1);
	}
	send_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (send_socket < 0) {
		perror("create socket failed: ");
		exit(1);
	}
	log_txt = fopen("log.txt", "w");
	if (log_txt < 0) {
		perror("open log failed: ");
		exit(1);
	}

	// Initialize variables to some default value
	source_mac = destination_mac = source_ip = destination_ip = source_port = destination_port = "";
	time_to_live = device_name = device_ind = "";

	use_tcp = rst_probe = false;

	// Get command line options
	source_mac = get_cmd_option("--se");
	destination_mac = get_cmd_option("--de");
	source_ip = get_cmd_option("--si");
	destination_ip = get_cmd_option("--di");
	source_port = get_cmd_option("--sp");
	destination_port = get_cmd_option("--dp");
	time_to_live = get_cmd_option("--ttl");
	device_name = get_cmd_option("--interface");
	device_ind = get_cmd_option("--devind");
	
	string p = get_cmd_option("--tcp");
	if (!p.empty()) {
		use_tcp = true;
	}	
	p = get_cmd_option("--rstprobe");
	if (!p.empty()) {
		rst_probe = true;
	}
	
	if (destination_ip.empty()) {
		fprintf(stderr, "Please provide a destination IP address.\n\n");
		fprintf(stderr, "Usage: ./myping --di <dst_ip>\n");
		fprintf(stderr, "       ./myping --di <dst_ip> --si <src_ip> --de <dst_mac> --se <src_mac> --dp <dst_port> --sp <src_port> --ttl <time_to_live> --interface <network_interface_name> --devind <network_interface_index>\n");

		exit(1);
	}
}


void tcp_loop(Packet &pkt, bool rst) {
	// Start with a random seqno
	unsigned long tcp_seq = rand() % (0xFFFFFFFF);
	pkt.send_tcp(send_socket, tcp_seq, rst);
	
	// Get ports
	unsigned short s_p = pkt.get_src_port();
	unsigned short d_p = pkt.get_dst_port();

	// Start measuring time passed since last send
	auto t1 = timestamp();
	auto last_send = t1;
	
	// Use a hashmap to store the time of the last send for each seqno
	ts_map[tcp_seq] = last_send;

	// Main TCP loop
	while (true) {
		// Receive a packet
		int res = pkt.receive(recv_socket);
		unsigned short s_port = pkt.get_src_port();
		unsigned short d_port = pkt.get_dst_port();
		unsigned int _seq = ntohl(pkt.get_tcp_ack_seq()) - 1;
		
		// Store the time we received it
		auto t2 = timestamp();
			
		if (res < 0) {
			if (timedif(t1, t2) > EXIT_TIMER) {
				fprintf(stderr, "Connection timeout.  Exiting...\n");
				break;
			}
		}
		else if (res == 0) {
			//cout << "\t(sent)\t";
		}
		else if (s_port == d_p && d_port == s_p) {		
			// Verify the response was correct
			if (pkt.isRst() == rst) {
				struct timeval send_t = ts_map[_seq];
				if (rst)
					send_t = ts_map[tcp_seq];
				// Find the round trip time
				double rtt = (double)timedif(send_t, t2) / 1000.0;
				// Print results
				cout << res << " bytes from " << pkt.get_src_ip()
				     << "\tSYN=" << pkt.isSyn() << " ACK=" << pkt.isAck() << " RST=" << pkt.isRst()
				     << ", rtt=" << rtt << " ms" << endl;
				// update the timestamp
				t1 = t2;
				pkt.log();
			}
		}

		// If more than a second has passed, send again
		if (timedif(last_send, t2) > SEC) {
			if (rst == false)			
				tcp_seq = rand() % (0xFFFFFFFF);
			pkt.send_tcp(send_socket, tcp_seq, rst);
			ts_map[tcp_seq] = t2;
			last_send = t2;
		}
	}
}


void echo_loop(Packet &pkt) {
	// Start with a random id/seqno
	unsigned short id = rand() % (0xFFFF + 1);
	unsigned short seq = rand() % (0xFFFF + 1);
	unsigned short start_seq = seq;

	// Send the initial packet
	pkt.send_echo(send_socket, id, seq);

	// Start measuring time since last send
	auto t1 = timestamp();
	auto last_send = t1;

	// Store the time of last send for each seqno
	ts_map[seq] = last_send;

	// Main ICMP loop
	while (true) {
		// Receive a packet
		int res = pkt.receive(recv_socket);
		unsigned short _id = pkt.get_echo_id();
		unsigned short _seq = pkt.get_echo_seq();
		
		// Record the time it was received
		auto t2 = timestamp();
		if (res < 0) {
			if (timedif(t1, t2) > EXIT_TIMER) {
				fprintf(stderr, "Connection timeout.  Exiting...\n");
				break;
			}
		}
		else if (res == 0) {
			//cout << "\t(sent)\t";
		}
		// Make sure the ID is correct
		else if (_id == id && ts_map.count(_seq) > 0){
			// Get the round trip time
			struct timeval send_t = ts_map[_seq];
			double rtt = (double)timedif(send_t, t2) / 1000.0;
			// Print results
			cout << res << " bytes from " << pkt.get_src_ip()
			     << "\ticmp_seq=" << _seq - start_seq + 1 << ", rtt=" << rtt << " ms" << endl;
			// Update timestamp, seqno
			t1 = t2;
			seq++;
			pkt.log();
		}

		// Check whether it's time to send another packet
		if (timedif(last_send, t2) > SEC) {
			pkt.send_echo(send_socket, id, seq);
			ts_map[seq] = t2;
			last_send = t2;
		}
	}
}

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++)
		args.push_back(argv[i]);

	// Some setup
	init();

	// Create a packet to send
	Packet pkt(log_txt);
	pkt.init(send_socket,
		 source_ip, destination_ip,
		 source_mac, destination_mac,
		 source_port, destination_port,
		 time_to_live,
		 use_tcp, rst_probe,
		 device_name, device_ind);

	// Determine which ping mode to use
	if (use_tcp || rst_probe)
		tcp_loop(pkt, rst_probe);
	else
		echo_loop(pkt);

	// Clean up
	close(recv_socket);
	fclose(log_txt);
	return 0;
}
