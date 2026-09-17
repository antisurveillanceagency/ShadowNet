#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <math.h> 
#include <netdb.h>
#include <signal.h>

unsigned short csum(unsigned short *ptr, int nbytes) {
	long sum;
	unsigned short oddbyte;
	short answer;
	sum = 0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if(nbytes == 1) {
		oddbyte = 0;
		*((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (short)~sum;
	return answer;
}

void inject_entropy_pulse(int *sock_ptr, struct sockaddr_in *target, int mark) {
	char packet[128];
	memset(packet, 0, 128);
	
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	
	unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
	FILE *f_hdr = fopen("/dev/urandom", "rb");
	if (f_hdr) {
		if (fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr) != 1) r_ip_id = 0;
		if (fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr) != 1) r_src_ip = 0;
		if (fread(&r_tos, sizeof(r_tos), 1, f_hdr) != 1) r_tos = 0;
		fclose(f_hdr);
	} else {
		r_ip_id = 11; r_src_ip = 22; r_tos = 33;
	}
	
	int payload_len = 64;
	int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
	
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = r_tos % 256;
	iph->tot_len = htons(total_len);
	iph->id = htons(r_ip_id % 65535);
	iph->frag_off = 0;
	iph->ttl = 64 + (r_tos % 65);
	iph->protocol = IPPROTO_TCP;
	iph->daddr = target->sin_addr.s_addr;
	
	iph->check = csum((unsigned short *) packet, total_len);
	
	tcph->source = htons(1024 + (r_ip_id % 64511));
	tcph->dest = target->sin_port;
	tcph->doff = 5;
	tcph->check = 0;
	
	char *data_payload = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
	data_payload[0] = (char)(r_ip_id & 0xFF);
	data_payload[1] = (char)(r_src_ip & 0xFF);
	data_payload[2] = 0x01; 
	data_payload[3] = (char)((r_ip_id >> 8) & 0xFF);
	
	if (send(*sock_ptr, packet, total_len, MSG_NOSIGNAL) < 0) {
		close(*sock_ptr);
		*sock_ptr = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(*sock_ptr, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		connect(*sock_ptr, (struct sockaddr*)target, sizeof(*target));
		send(*sock_ptr, packet, total_len, MSG_NOSIGNAL);
	}
}

double get_loopix_engine_delay(double lambda) {
	unsigned int raw_entropy = 0;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(&raw_entropy, sizeof(raw_entropy), 1, f) != 1) raw_entropy = 1;
		fclose(f);
	}
	double u = (double)raw_entropy / 4294967295.0;
	if (u <= 0.0) u = 0.000001;
	return -log(u) / lambda;
}

int main(int argc, char *argv[]) {
	if (argc < 11) return 1;
	signal(SIGPIPE, SIG_IGN);
	
	const char *targets[10];
	for (int i = 0; i < 10; i++) {
		targets[i] = argv[i + 1];
	}
	
	int socks[10];
	struct sockaddr_in sins[10];
	int mark = 76;
	
	for (int i = 0; i < 10; i++) {
		socks[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (socks[i] < 0) exit(1);
		
		setsockopt(socks[i], SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		memset(&sins[i], 0, sizeof(sins[i]));
		sins[i].sin_family = AF_INET;
		sins[i].sin_port = htons(443);
		
		struct hostent *he = gethostbyname(targets[i]);
		if (he) {
			memcpy(&sins[i].sin_addr, he->h_addr_list[0], he->h_length);
		} else {
			sins[i].sin_addr.s_addr = inet_addr(targets[i]);
		}
		connect(socks[i], (struct sockaddr*)&sins[i], sizeof(sins[i]));
	}
	
	while(1) {
		unsigned char r_idx = 0;
		FILE *f_ri = fopen("/dev/urandom", "rb");
		if (f_ri) { if (fread(&r_idx, 1, 1, f_ri) != 1) r_idx = 0; fclose(f_ri); }
		int idx = r_idx % 10;
		
		inject_entropy_pulse(&socks[idx], &sins[idx], mark);
		
		struct timespec ts;
		
		double poisson_interval = get_loopix_engine_delay(35.0); 
		ts.tv_sec = (long)poisson_interval;
		ts.tv_nsec = (long)((poisson_interval - ts.tv_sec) * 1000000000.0) % 1000000000L;
		
		nanosleep(&ts, NULL);
	}
	return 0;
}
