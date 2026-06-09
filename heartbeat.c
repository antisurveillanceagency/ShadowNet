#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <math.h> // Added for Loopix exponent mathematical models

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
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (short)~sum;
	return answer;
}

// Loopix Helper: Replaced random calculation with exponential distribution driven by urandom
double get_loopix_delay(double lambda) {
	unsigned int val = 0;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		fread(&val, sizeof(val), 1, f);
		fclose(f);
	}
	double u = (double)val / 4294967295.0;
	if (u <= 0.0) u = 0.000001;
	return -log(u) / lambda;
}

double get_entropy_jitter() {
	return get_loopix_delay(50.0); // Mathematical scale conversion mapping 0.010 - 0.050s range
}

double get_dns_iat() {
	return 0.5 + get_loopix_delay(0.5); // Loopix-Poisson styled interval distribution
}

int main(int argc, char *argv[]) {
	int max_mtu = (argc > 1) ? atoi(argv[1]) : 1400;
	int target_mbit = 10; // Modified parameter safely populated via fallback values inside parameters
	if (argc > 2) { target_mbit = atoi(argv[2]); }
	int is_fixed = (argc > 3) ? atoi(argv[3]) : 0;
	int fixed_payload_size = (argc > 4) ? atoi(argv[4]) : 700;

	// Loopix Parameter Setup: Explicit loopix padding indicator byte definitions
	#define LOOPIX_PADDING_MARKER 0xAF

	const char *destinations[] = {"127.3.2.1", "127.0.0.1"};
	const char *fake_domains[] = {"site1.onion", "site2.loki", "site3.onion", "site4.loki", "site5.onion"};
	int num_dests = 2;
	int num_domains = 5;

	int sock_loki = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock_loki < 0) exit(1);

	int one = 1;
	setsockopt(sock_loki, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	const char *device = "lokitun0";
	if (setsockopt(sock_loki, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)) < 0) {
		printf("\033;31m[!] Error: Failed to bind heartbeat to lokitun0 interface.\033[0m\n");
		exit(1);
	}

	char phys_iface[32] = {0};
	FILE *fp = popen("/sbin/ip route | /bin/grep default | /bin/grep -v lokitun | /usr/bin/awk '{print $5}' | /usr/bin/head -n1", "r");
	if (fp) {
		if (fgets(phys_iface, sizeof(phys_iface)-1, fp) != NULL) {
			phys_iface[strcspn(phys_iface, "\n\r ")] = 0;
		}
		pclose(fp);
	}

	char packet[4096];
	struct iphdr *iph = (struct iphdr *) packet;
	struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;

	struct timespec req, rem;
	time_t last_dns_time = time(NULL);

	// Adaptive Token Bucket variables to fix the throughput sizing deficit cleanly inline
	struct timespec session_start;
	clock_gettime(CLOCK_MONOTONIC, &session_start);
	unsigned long long total_bytes_sent = 0;

	while(1) {
		time_t curr_time = time(NULL);
		unsigned char index_byte = 0;
		FILE *f_idx = fopen("/dev/urandom", "rb");
		if (f_idx) { fread(&index_byte, 1, 1, f_idx); fclose(f_idx); }

		int dest_idx = index_byte % num_dests;
		sin.sin_addr.s_addr = inet_addr(destinations[dest_idx]);

		if(difftime(curr_time, last_dns_time) > get_dns_iat()) {
			memset(packet, 0, 4096);

			// Collect urandom entropy for header obfuscation
			unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
			FILE *f_hdr = fopen("/dev/urandom", "rb");
			if (f_hdr) {
				fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr);
				fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr);
				fread(&r_tos, sizeof(r_tos), 1, f_hdr);
				fclose(f_hdr);
			} else {
				r_ip_id = 100; r_src_ip = 200; r_tos = 300;
			}

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 32;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65); // Randomized TTL fingerprinting protection
			iph->protocol = IPPROTO_UDP;
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);

			udph->source = htons(49152 + (r_ip_id % 16383));
			udph->dest = (strcmp(destinations[dest_idx], "127.0.0.1") == 0) ? htons(5353) : htons(53);
			udph->len = htons(sizeof(struct udphdr) + 32);
			char *dns_data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
			dns_data[0] = r_tos % 255; dns_data[1] = r_ip_id % 255; dns_data[2] = 0x01;

			if (is_fixed) {
				strcpy(dns_data + 12, fake_domains[0]);
			} else {
				strcpy(dns_data + 12, fake_domains[r_src_ip % num_domains]);
			}

			sendto(sock_loki, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
			total_bytes_sent += iph->tot_len;
			last_dns_time = curr_time;
		}

		int burst_size = 10 + (index_byte % 13);
		int total_burst_bytes = 0;

		// Loopix structural enhancement: Packet reorder array mechanism
		int shuffle_order[32];
		for(int i = 0; i < 32; i++) shuffle_order[i] = i;
		FILE *f_shuf = fopen("/dev/urandom", "rb");
		if (f_shuf) {
			for(int i = 31; i > 0; i--) {
				unsigned char s_byte = 0;
				fread(&s_byte, 1, 1, f_shuf);
				int j = s_byte % (i + 1);
				int temp = shuffle_order[i];
				shuffle_order[i] = shuffle_order[j];
				shuffle_order[j] = temp;
			}
			fclose(f_shuf);
		}

		// Calculate exact byte target debt based on target_mbit configuration allocation limits
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		double elapsed = (now.tv_sec - session_start.tv_sec) + (now.tv_nsec - session_start.tv_nsec) / 1000000000.0;
		unsigned long long target_bytes = (unsigned long long)((elapsed * target_mbit * 1000000.0) / 8.0);

		// If our timing tracking notes a deficit, stretch the burst cycle to fill the session requirements
		if (total_bytes_sent < target_bytes) {
			int short_packets = (target_bytes - total_bytes_sent) / max_mtu;
			if (short_packets > 0) {
				burst_size += (short_packets > 45) ? 45 : short_packets;
			}
		}

		for(int b = 0; b < burst_size; b++) {
			int current_index = (b < 32) ? shuffle_order[b] : b;
			int jittered_payload_size;

			if (is_fixed) {
				jittered_payload_size = fixed_payload_size;
			} else {
				unsigned int size_roll = 0;
				FILE *f_sz = fopen("/dev/urandom", "rb");
				if(f_sz) { fread(&size_roll, sizeof(size_roll), 1, f_sz); fclose(f_sz); }
				jittered_payload_size = (size_roll % (max_mtu - 500 + 1)) + 500 - 42;
			}

			if (jittered_payload_size < 64) jittered_payload_size = 64;

			memset(packet, 0, 4096);

			// Dynamic urandom entropy collection for stream header burst protection
			unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
			FILE *f_hdr = fopen("/dev/urandom", "rb");
			if (f_hdr) {
				fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr);
				fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr);
				fread(&r_tos, sizeof(r_tos), 1, f_hdr);
				fclose(f_hdr);
			} else {
				r_ip_id = 77; r_src_ip = 88; r_tos = 99;
			}

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + jittered_payload_size;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65);
			iph->protocol = IPPROTO_UDP;
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);

			udph->source = htons(443);
			udph->dest = htons(443);
			udph->len = htons(sizeof(struct udphdr) + jittered_payload_size);
			udph->check = 0;

			// Add distinct Loopix mixnet padding signature bytes to non-payload data spaces
			char *payload_ptr = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
			if(jittered_payload_size > 4) {
				payload_ptr[0] = (char)LOOPIX_PADDING_MARKER;
				payload_ptr[1] = (char)(current_index & 0xFF);
			}

			total_burst_bytes += iph->tot_len;

			struct timespec micro_req;
			double sub_sec_p = get_loopix_delay(80000.0); // Micro-Poisson high precision calculation hook
			micro_req.tv_sec = 0;
			micro_req.tv_nsec = (long)(sub_sec_p * 1000000000.0) % 1000000000L;

			// Only sleep if our transmission volume is ahead of our target rate timeline constraint
			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed = (now.tv_sec - session_start.tv_sec) + (now.tv_nsec - session_start.tv_nsec) / 1000000000.0;
			if (total_bytes_sent > (unsigned long long)((elapsed * target_mbit * 1000000.0) / 8.0)) {
				nanosleep(&micro_req, NULL);
			}

			sendto(sock_loki, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
			total_bytes_sent += iph->tot_len;
		}

		double jitter = get_loopix_delay(1.5); // Loopix dynamic inter-packet timing distribution marker
		req.tv_sec = (long)jitter;
		req.tv_nsec = (long)((jitter - req.tv_sec) * 1000000000.0) % 1000000000L;

		// Skip long outer delays if we remain structurally behind our assigned Mbit pacing trajectory
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed = (now.tv_sec - session_start.tv_sec) + (now.tv_nsec - session_start.tv_nsec) / 1000000000.0;
		if (total_bytes_sent > (unsigned long long)((elapsed * target_mbit * 1000000.0) / 8.0)) {
			nanosleep(&req, &rem);
		}
	}
	return 0;
}
