#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <math.h> // Added for Loopix exponent mathematical models

// FIXED: Integrated the identical structural Internet checksum calculation utility function directly to fix the linker error
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

void inject_entropy_pulse(int sock, struct sockaddr_in *target) {
	// Upgraded buffer length to host full Custom IP + UDP header generation block
	char packet[128];
	memset(packet, 0, 128);

	struct iphdr *iph = (struct iphdr *) packet;
	struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));

	// Dynamic entropy collection for raw structural layer randomization
	unsigned int r_ip_id = 0, r_src_ip = 0, r_tos = 0;
	FILE *f_hdr = fopen("/dev/urandom", "rb");
	if (f_hdr) {
		fread(&r_ip_id, sizeof(r_ip_id), 1, f_hdr);
		fread(&r_src_ip, sizeof(r_src_ip), 1, f_hdr);
		fread(&r_tos, sizeof(r_tos), 1, f_hdr);
		fclose(f_hdr);
	} else {
		r_ip_id = 11; r_src_ip = 22; r_tos = 33;
	}

	int payload_len = 64;
	int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

	// Custom Raw IP Layer Setup
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = r_tos % 256;
	iph->tot_len = htons(total_len);
	iph->id = htons(r_ip_id % 65535);
	iph->frag_off = 0;
	iph->ttl = 64 + (r_tos % 65);
	iph->protocol = IPPROTO_UDP;
	iph->daddr = target->sin_addr.s_addr;

	// Checksum calculation over full header block area
	iph->check = csum((unsigned short *) packet, total_len);

	// Setup UDP Layer directly inside the sequence
	udph->source = htons(1024 + (r_ip_id % 64511));
	udph->dest = target->sin_port;
	udph->len = htons(sizeof(struct udphdr) + payload_len);
	udph->check = 0;

	// Generate the internal entropy payload block directly matching the exact signature
	char *data_payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
	data_payload[0] = (char)(r_ip_id & 0xFF);
	data_payload[1] = (char)(r_src_ip & 0xFF);
	data_payload[2] = 0x01; // Loopix constant control flow flag placeholder

	sendto(sock, packet, total_len, 0, (struct sockaddr*)target, sizeof(*target));
}

// Loopix Helper: Generates exponential distribution delay values using urandom factor fields
double get_loopix_engine_delay(double lambda) {
	unsigned int raw_entropy = 0;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		fread(&raw_entropy, sizeof(raw_entropy), 1, f);
		fclose(f);
	}
	double u = (double)raw_entropy / 4294967295.0;
	if (u <= 0.0) u = 0.000001;
	return -log(u) / lambda;
}

int main(int argc, char *argv[]) {
	if (argc < 2) return 1;

	// Shifted from IPPROTO_UDP to IPPROTO_RAW to explicitly support manual IP Header Insertion processing loops
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) exit(1);

	int one = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lokitun0", 8) < 0) {
		exit(1);
	}
	struct sockaddr_in target;
	target.sin_family = AF_INET;

	unsigned int arg_check = 0;
	FILE *f_arg = fopen("/dev/urandom", "rb");
	if(f_arg) { fread(&arg_check, sizeof(arg_check), 1, f_arg); fclose(f_arg); }

	target.sin_port = (strcmp(argv[1], "127.0.0.1") == 0) ? htons(5353) : htons(53);
	target.sin_addr.s_addr = inet_addr(argv[1]);

	while(1) {
		inject_entropy_pulse(sock, &target);
		struct timespec ts;

		// Enforce continuous Loopix Poisson processing interval loops
		double poisson_interval = get_loopix_engine_delay(35.0); // Aligns timeline scale execution factors
		ts.tv_sec = (long)poisson_interval;
		ts.tv_nsec = (long)((poisson_interval - ts.tv_sec) * 1000000000.0) % 1000000000L;

		nanosleep(&ts, NULL);
	}
	return 0;
}
