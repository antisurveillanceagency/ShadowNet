#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
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

double get_loopix_delay(double lambda) {
	unsigned int val = 0;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(&val, sizeof(val), 1, f) != 1) val = 1;
		fclose(f);
	}
	double u = (double)val / 4294967295.0;
	if (u <= 0.0) u = 0.000001;
	return -log(u) / lambda;
}

double get_entropy_jitter() {
	return get_loopix_delay(50.0); 
}

double get_dns_iat() {
	return 0.5 + get_loopix_delay(0.5); 
}

int main(int argc, char *argv[]) {
	signal(SIGPIPE, SIG_IGN); 
	
	int max_mtu = (argc > 1) ? atoi(argv[1]) : 1400;
	int target_kbps = 1000; 
	if (argc > 2) { target_kbps = atoi(argv[2]); }
	int is_fixed = (argc > 3) ? atoi(argv[3]) : 0;
	int is_fixed_payload = (argc > 4) ? atoi(argv[4]) : 700;
	
	const char *targets[10];
	targets[0] = (argc > 5) ? argv[5] : "duckduckgo.com";
	targets[1] = (argc > 6) ? argv[6] : "google.com";
	targets[2] = (argc > 7) ? argv[7] : "startpage.com";
	targets[3] = (argc > 8) ? argv[8] : "wikipedia.org";
	targets[4] = (argc > 9) ? argv[9] : "mozilla.org";
	targets[5] = (argc > 10) ? argv[10] : "debian.org";
	targets[6] = (argc > 11) ? argv[11] : "kernel.org";
	targets[7] = (argc > 12) ? argv[12] : "github.com";
	targets[8] = (argc > 13) ? argv[13] : "archlinux.org";
	targets[9] = (argc > 14) ? argv[14] : "eff.org";
	
	#define LOOPIX_PADDING_MARKER 0xAF
	
	const char *destinations[] = {"127.3.2.1", "127.0.0.1"};
	const char *fake_domains[] = {"site1.onion", "site2.onion", "site3.onion", "site4.onion", "site5.onion"};
	int num_dests = 2;
	int num_domains = 5;
	
	int socks[10];
	struct sockaddr_in sins[10];
	int mark = 76;
	
	for (int i = 0; i < 10; i++) {
		socks[i] = socket(AF_INET, SOCK_STREAM, 0);
		if(socks[i] < 0) exit(1);
		
		if (setsockopt(socks[i], SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
			printf("\033[0;31m[!] Error: Failed to set socket mark 76 | Co Authored By JS / ASA.\033[0m\n");
			exit(1);
		}
		
		memset(&sins[i], 0, sizeof(sins[i]));
		sins[i].sin_family = AF_INET;
		sins[i].sin_port = htons(443);
		
		struct hostent *he = gethostbyname(targets[i]);
		if (he) {
			memcpy(&sins[i].sin_addr, he->h_addr_list[0], he->h_length);
		} else {
			sins[i].sin_addr.s_addr = inet_addr("1.1.1.1");
		}
		connect(socks[i], (struct sockaddr *)&sins[i], sizeof(sins[i]));
	}
	
	char packet[4096];
	struct iphdr *iph = (struct iphdr *) packet;
	struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
	
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	
	struct timespec req, rem;
	time_t last_dns_time = time(NULL);
	
	while(1) {
		time_t curr_time = time(NULL);
		unsigned char index_byte = 0;
		FILE *f_idx = fopen("/dev/urandom", "rb");
		if (f_idx) { if (fread(&index_byte, 1, 1, f_idx) != 1) index_byte = 0; fclose(f_idx); }
		
		int tgt_idx = index_byte % 10;
		sin.sin_addr.s_addr = sins[tgt_idx].sin_addr.s_addr;
		
		if(difftime(curr_time, last_dns_time) > get_dns_iat()) {
			memset(packet, 0, 4096);
			
			unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
			FILE *f_hdr = fopen("/dev/urandom", "rb");
			if (f_hdr) {
				if (fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr) != 1) r_ip_id = 0;
				if (fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr) != 1) r_src_ip = 0;
				if (fread(&r_tos, sizeof(r_tos), 1, f_hdr) != 1) r_tos = 0;
				fclose(f_hdr);
			} else {
				r_ip_id = 100; r_src_ip = 200; r_tos = 300;
			}
			
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 32;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65); 
			iph->protocol = IPPROTO_TCP;
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);
			
			tcph->source = htons(49152 + (r_ip_id % 16383));
			tcph->dest = htons(5353); 
			char *dns_data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
			dns_data[0] = r_tos % 255; dns_data[1] = r_ip_id % 255; dns_data[2] = 0x01;
			
			if (is_fixed) {
				strcpy(dns_data + 12, fake_domains[0]);
			} else {
				strcpy(dns_data + 12, fake_domains[r_src_ip % num_domains]);
			}
			
			if (send(socks[tgt_idx], packet, iph->tot_len, MSG_NOSIGNAL) < 0) {
				close(socks[tgt_idx]);
				socks[tgt_idx] = socket(AF_INET, SOCK_STREAM, 0);
				setsockopt(socks[tgt_idx], SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
				connect(socks[tgt_idx], (struct sockaddr *)&sins[tgt_idx], sizeof(sins[tgt_idx]));
				send(socks[tgt_idx], packet, iph->tot_len, MSG_NOSIGNAL);
			}
			last_dns_time = curr_time;
		}
		
		int burst_size = 10 + (index_byte % 13);
		
		int shuffle_order[32];
		for(int i = 0; i < 32; i++) shuffle_order[i] = i;
		FILE *f_shuf = fopen("/dev/urandom", "rb");
		if (f_shuf) {
			for(int i = 31; i > 0; i--) {
				unsigned char s_byte = 0;
				if (fread(&s_byte, 1, 1, f_shuf) == 1) {
					int j = s_byte % (i + 1);
					int temp = shuffle_order[i];
					shuffle_order[i] = shuffle_order[j];
					shuffle_order[j] = temp;
				}
			}
			fclose(f_shuf);
		}
		
		for(int b = 0; b < burst_size; b++) {
			int current_index = (b < 32) ? shuffle_order[b] : b;
			int jittered_payload_size;
			
			if (is_fixed) {
				jittered_payload_size = is_fixed_payload;
			} else {
				unsigned int size_roll = 0;
				FILE *f_sz = fopen("/dev/urandom", "rb");
				if(f_sz) { if (fread(&size_roll, sizeof(size_roll), 1, f_sz) != 1) size_roll = 0; fclose(f_sz); }
				jittered_payload_size = (size_roll % (max_mtu - 500 + 1)) + 500 - 42;
			}
			
			if (jittered_payload_size < 64) jittered_payload_size = 64;
			
			memset(packet, 0, 4096);
			
			unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
			FILE *f_hdr = fopen("/dev/urandom", "rb");
			if (f_hdr) {
				if (fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr) != 1) r_ip_id = 0;
				if (fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr) != 1) r_src_ip = 0;
				if (fread(&r_tos, sizeof(r_tos), 1, f_hdr) != 1) r_tos = 0;
				fclose(f_hdr);
			} else {
				r_ip_id = 77; r_src_ip = 88; r_tos = 99;
			}
			
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + jittered_payload_size;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65);
			iph->protocol = IPPROTO_TCP;
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);
			
			tcph->source = htons(443);
			tcph->dest = htons(443);
			tcph->doff = 5;
			tcph->check = 0;
			
			char *payload_ptr = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
			if(jittered_payload_size > 4) {
				payload_ptr[0] = (char)LOOPIX_PADDING_MARKER;
				payload_ptr[1] = (char)(current_index & 0xFF);
				payload_ptr[2] = (char)((r_ip_id >> 4) & 0xFF);
				payload_ptr[3] = (char)((r_src_ip >> 4) & 0xFF);
			}
			
			struct timespec micro_req;
			double sub_sec_p = get_loopix_delay(80000.0); 
			micro_req.tv_sec = 0;
			micro_req.tv_nsec = (long)(sub_sec_p * 1000000000.0) % 1000000000L;
			
			nanosleep(&micro_req, NULL);
			
			if (send(socks[tgt_idx], packet, iph->tot_len, MSG_NOSIGNAL) < 0) {
				close(socks[tgt_idx]);
				socks[tgt_idx] = socket(AF_INET, SOCK_STREAM, 0);
				setsockopt(socks[tgt_idx], SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
				connect(socks[tgt_idx], (struct sockaddr *)&sins[tgt_idx], sizeof(sins[tgt_idx]));
				send(socks[tgt_idx], packet, iph->tot_len, MSG_NOSIGNAL);
			}
		}
		
		double jitter = get_loopix_delay(1.5); 
		req.tv_sec = (long)jitter;
		req.tv_nsec = (long)((jitter - req.tv_sec) * 1000000000.0) % 1000000000L;
		
		nanosleep(&req, &rem);
	}
	return 0;
}
