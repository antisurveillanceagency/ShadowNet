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

double get_entropy_jitter() {
	unsigned char rand_byte;
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f) return 0.010;
	fread(&rand_byte, 1, 1, f);
	fclose(f);
	return ((double)rand_byte / 255.0) * 0.040 + 0.010;
}

double get_dns_iat() {
	unsigned int rand_val;
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f) return 1.0;
	fread(&rand_val, sizeof(rand_val), 1, f);
	fclose(f);
	return 0.5 + ((double)(rand_val % 2500) / 1000.0);
}

int main(int argc, char *argv[]) {
	int max_mtu = (argc > 1) ? atoi(argv[1]) : 1400;
	int target_mbit = (argc > 2) ? atoi(argv[2]) : (5 + (rand() % 16));
	int is_fixed = (argc > 3) ? atoi(argv[3]) : 0;
	int fixed_payload_size = (argc > 4) ? atoi(argv[4]) : ((rand() % (max_mtu - 500 + 1)) + 500 - 42);

	const char *destinations[] = {"127.3.2.1", "127.0.0.1"};
	const char *fake_domains[] = {"site1.onion", "site2.loki", "site3.onion", "site4.loki", "site5.onion"};
	int num_dests = 2;
	int num_domains = 5;

	srand(time(NULL));

	int sock_loki = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock_loki < 0) exit(1);

	int one = 1;
	setsockopt(sock_loki, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	const char *device = "lokitun0";
	if (setsockopt(sock_loki, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)) < 0) {
		printf("\033[0;31m[!] Error: Failed to bind heartbeat to lokitun0 interface.\033[0m\n");
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

	while(1) {
		time_t curr_time = time(NULL);
		int dest_idx = rand() % num_dests;
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
				r_ip_id = rand();
				r_src_ip = rand();
				r_tos = rand();
			}

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 32;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65); // Randomized TTL fingerprinting protection
			iph->protocol = IPPROTO_UDP;
			iph->saddr = r_src_ip; // Fully randomized source IP injection
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);

			udph->source = htons(49152 + (rand() % 16383));
			udph->dest = (strcmp(destinations[dest_idx], "127.0.0.1") == 0) ? htons(5353) : htons(53);
			udph->len = htons(sizeof(struct udphdr) + 32);
			char *dns_data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
			dns_data[0] = rand() % 255; dns_data[1] = rand() % 255; dns_data[2] = 0x01;

			if (is_fixed) {
				strcpy(dns_data + 12, fake_domains[0]);
			} else {
				strcpy(dns_data + 12, fake_domains[rand() % num_domains]);
			}

			sendto(sock_loki, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
			last_dns_time = curr_time;
		}

		int burst_size = 10 + (rand() % 13);
		int total_burst_bytes = 0;

		for(int b = 0; b < burst_size; b++) {
			int jittered_payload_size;

			if (is_fixed) {
				jittered_payload_size = fixed_payload_size;
			} else {
				jittered_payload_size = (rand() % (max_mtu - 500 + 1)) + 500 - 42;
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
				r_ip_id = rand();
				r_src_ip = rand();
				r_tos = rand();
			}

			iph->ihl = 5;
			iph->version = 4;
			iph->tos = r_tos % 256;
			iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + jittered_payload_size;
			iph->id = htons(r_ip_id % 65535);
			iph->frag_off = 0;
			iph->ttl = 64 + (r_tos % 65);
			iph->protocol = IPPROTO_UDP;
			iph->saddr = r_src_ip; // Fully randomized source IP injection
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short *) packet, iph->tot_len);

			udph->source = htons(443);
			udph->dest = htons(443);
			udph->len = htons(sizeof(struct udphdr) + jittered_payload_size);
			udph->check = 0;

			total_burst_bytes += iph->tot_len;

			struct timespec micro_req;
			micro_req.tv_sec = 0;
			unsigned int urand_buf[2] = {0, 0};
			FILE *f_urand = fopen("/dev/urandom", "rb");
			if (f_urand) {
				fread(urand_buf, sizeof(unsigned int), 2, f_urand);
				fclose(f_urand);
			} else {
				urand_buf[0] = rand();
				urand_buf[1] = rand();
			}
			micro_req.tv_nsec = (urand_buf[0] % 25000) + (urand_buf[1] % 15000);
			nanosleep(&micro_req, NULL);

			sendto(sock_loki, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
		}

		double required_time = (double)total_burst_bytes / (target_mbit * 125000.0);
		unsigned char urand_j = 0;
		FILE *f_urand_j = fopen("/dev/urandom", "rb");
		if (f_urand_j) {
			fread(&urand_j, 1, 1, f_urand_j);
			fclose(f_urand_j);
		} else {
			urand_j = rand() % 10;
		}
		double jitter = required_time * (0.95 + ((double)(urand_j % 10) / 100.0));

		req.tv_sec = (long)jitter;
		req.tv_nsec = (long)((jitter - req.tv_sec) * 1000000000.0);
		nanosleep(&req, &rem);
	}
	return 0;
}
