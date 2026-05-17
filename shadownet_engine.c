#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void inject_entropy_pulse(int sock, struct sockaddr_in *target) {
	char packet[64];
	memset(packet, 0, 64);
	packet[0] = (char)rand(); packet[1] = (char)rand();
	packet[2] = 0x01;
	sendto(sock, packet, 64, 0, (struct sockaddr*)target, sizeof(*target));
}

int main(int argc, char *argv[]) {
	if (argc < 2) return 1;
	srand(time(NULL));
	
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lokitun0", 8) < 0) {
		exit(1);
	}
	struct sockaddr_in target;
	target.sin_family = AF_INET;
	target.sin_port = htons(53);
	target.sin_addr.s_addr = inet_addr(argv[1]);
	
	while(1) {
		inject_entropy_pulse(sock, &target);
		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = (10 + (rand() % 40)) * 1000000L;
		nanosleep(&ts, NULL);
	}
	return 0;
}
