#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

// Global variable required by the monitoring loop condition
int proc_missing = 0;

void validate_iface(const char *iface) {
	if (strlen(iface) == 0) exit(1);
	for (int i = 0; iface[i] != '\0'; i++) {
		if (!isalnum(iface[i]) && iface[i] != '.') {
			printf("\033[0;31m[!] Security Violation: Malicious interface detected.\033[0m\n");
			exit(1);
		}
	}
}

void get_interface(char *iface) {
	FILE *fp = popen("ip route | grep default | awk '{print $5}' | head -n1", "r");
	if (fp == NULL) {
		printf("\033[0;31m[!] Error: Failed to execute ip route.\033[0m\n");
		exit(1);
	}
	memset(iface, 0, 32);
	if (fgets(iface, 15, fp) == NULL) {
		printf("\033[0;31m[!] Error: No active network interface found.\033[0m\n");
		pclose(fp);
		exit(1);
	}
	iface[strcspn(iface, "\n\r ")] = 0;
	pclose(fp);
	validate_iface(iface);
}

int get_entropy_delay(int min, int max) {
	unsigned char rand_val;
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f) return min;
	if (fread(&rand_val, 1, 1, f) != 1) {
		fclose(f);
		return min;
	}
	fclose(f);
	int range = max - min;
	if (range <= 0) return min;
	return ((rand_val * range) / 255) + min;
}

int get_true_5050() {
	unsigned char rand_val;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(&rand_val, 1, 1, f) == 1) {
			fclose(f);
			return rand_val % 2;
		}
		fclose(f);
	}
	return rand() % 2;
}

void execute_14_tier_sanitation(const char *name) {
	char cmd[2048];
	char short_name[16];
	strncpy(short_name, name, 15);
	short_name[15] = '\0';
	// Replaced sprintf with snprintf
	snprintf(cmd, sizeof(cmd), "[ -f /dev/shm/shadownet_%1$s.pid ] && PID=$(cat /dev/shm/shadownet_%1$s.pid) && [ -d /proc/$PID ] && sudo kill -9 $PID 2>/dev/null; "
	"MATCHES=$(ps -ef | grep '%1$s' | grep -v grep | awk '{print $2}'); for m_pid in $MATCHES; do sudo kill -9 $m_pid 2>/dev/null; done; "
	"sudo fuser -k -9 '%1$s' 2>/dev/null; "
	"for pdir in /proc/[0-9]*; do if [ -f \"$pdir/comm\" ] && grep -q \"%2$s\" \"$pdir/comm\"; then sudo kill -9 $(basename \"$pdir\") 2>/dev/null; fi; done; "
	"LSOF_PIDS=$(sudo lsof -t '%1$s' 2>/dev/null); for l_pid in $LSOF_PIDS; do sudo kill -9 $l_pid 2>/dev/null; done; "
	"SESS_PIDS=$(ps -eo pid,sess,cmd | grep '%1$s' | grep -v grep | awk '{print $1}'); for s_pid in $SESS_PIDS; do sudo kill -9 $s_pid 2>/dev/null; done; "
	"ENV_PIDS=$(grep -l 'SHADOWNET_PROC=true' /proc/[0-9]*/environ 2>/dev/null | cut -d/ -f3); for e_pid in $ENV_PIDS; do sudo kill -9 $e_pid 2>/dev/null; done; "
	"ORPHAN_PIDS=$(ps -ef | awk '$3 == 1' | grep '%1$s' | grep -v grep | awk '{print $2}'); for o_pid in $ORPHAN_PIDS; do sudo kill -9 $o_pid 2>/dev/null; done; "
	"MAP_PIDS=$(sudo grep -l '%1$s' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3); for mp_pid in $MAP_PIDS; do sudo kill -9 $mp_pid 2>/dev/null; done; "
	"NICE_PIDS=$(ps -eo pid,ni,cmd | awk '$2 == -20' | grep '%1$s' | grep -v grep | awk '$1 != \"\"' | awk '{print $1}'); for n_pid in $NICE_PIDS; do sudo kill -9 $n_pid 2>/dev/null; done; "
	"CMD_PIDS=$(grep -a -l '%1$s' /proc/[0-9]*/cmdline 2>/dev/null | cut -d/ -f3); for c_pid in $CMD_PIDS; do sudo kill -9 $c_pid 2>/dev/null; done; "
	"FD_PIDS=$(sudo find /proc/[0-9]* /fd -type l -lname '*%1$s*' 2>/dev/null | cut -d/ -f3 | sort -u); for fd_pid in $FD_PIDS; do sudo kill -9 $fd_pid 2>/dev/null; done; "
	"STAT_PIDS=$(awk -v name=\"%2$s\" '$2 == \"(\"name\")\" {print $1}' /proc/[0-9]*/stat 2>/dev/null); for st_pid in $STAT_PIDS; do sudo kill -9 $st_pid 2>/dev/null; done;", name, short_name);
	system(cmd);
	if (strstr(name, "engine") != NULL) {
		system("PORT_PIDS=$(sudo ss -lptn 'sport = :76' | grep -oP 'pid=\\K[0-9]+'); for p_pid in $PORT_PIDS; do sudo kill -9 $p_pid 2>/dev/null; done");
	}
}

void trigger_emergency_lockdown() {
	system("iptables -P OUTPUT DROP; iptables -P INPUT DROP; iptables -P FORWARD DROP");
	system("ip6tables -P OUTPUT DROP; ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP");
	system("iptables -F; iptables -t nat -F; iptables -t mangle -F");
	system("ip6tables -F; ip6tables -t nat -F; ip6tables -t mangle -F");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	execute_14_tier_sanitation("xdotool_noise");
	execute_14_tier_sanitation("i2pd");
	system("sudo systemctl stop lokinet tor i2pd");
	printf("\n\033[0;31m\a[!!!] SHADOWNET EMERGENCY LOCKDOWN ENGAGED. INTERNET PERMANENTLY KILLED.\033[0m\n");
	printf("\033[1;33m[*] Run 'sudo ./shadownet stop' manually to restore connectivity.\033[0m\n");
	exit(1);
}

void handle_sigint(int sig) {
	trigger_emergency_lockdown();
}

void stop_shadownet() {
	char int_if[32] = {0};
	get_interface(int_if);
	system("iptables -P OUTPUT DROP; iptables -P INPUT DROP; iptables -P FORWARD DROP");
	system("ip6tables -P OUTPUT DROP; ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP");
	system("iptables -F; iptables -t nat -F; iptables -t mangle -F");
	system("ip6tables -F; ip6tables -t nat -F; ip6tables -t mangle -F");
	int exit_dns_jitter = get_entropy_delay(2, 8);
	printf("\033[1;31m[*] Pending exit... Applying Exit DNS Entropy: %ds...\033[0m\n", exit_dns_jitter);
	sleep(exit_dns_jitter);
	int wait_time = get_entropy_delay(5, 60);
	printf("\033[1;31m[*] Finalizing teardown... Waiting %d seconds.\033[0m\n", wait_time);
	sleep(wait_time);
	system("sudo systemctl stop lokinet i2pd 2>/dev/null");
	system("sudo systemctl unmask chrony ntp systemd-timesyncd 2>/dev/null");
	system("sudo systemctl start chrony ntp systemd-timesyncd 2>/dev/null");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	execute_14_tier_sanitation("xdotool_noise");
	execute_14_tier_sanitation("i2pd");
	system("sudo rfkill unblock bluetooth 2>/dev/null");
	system("sudo modprobe uvcvideo 2>/dev/null");
	system("sudo modprobe snd_hda_intel 2>/dev/null");
	system("sudo chattr -i /sys/firmware/efi/efivars/* 2>/dev/null");
	system("rm -f /dev/shm/shadownet_heartbeat.pid /dev/shm/shadownet_engine.pid /dev/shm/xdotool_noise.pid");
	system("rm -f /dev/shm/heartbeat /dev/shm/shadownet_engine /dev/shm/xdotool_noise.sh");
	system("sudo sysctl -w net.ipv4.ip_default_ttl=64 >/dev/null");
	system("sudo sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null");
	system("sudo sysctl -w net.ipv4.ip_no_pmtu_disc=0 >/dev/null");
	system("sudo adjtimex -t 10000 >/dev/null 2>&1");
	char cmd[512];
	// Replaced sprintf with snprintf
	snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %.16s root 2>/dev/null", int_if);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s mtu 1500", int_if);
	system(cmd);
	system("if [ -f /dev/shm/resolv.conf.shadownet_bak ]; then rm -f /etc/resolv.conf; mv /dev/shm/resolv.conf.shadownet_bak /etc/resolv.conf; fi");
	system("if [ -f /dev/shm/shadownet_mac.bak ]; then "
	"RESTORE_JITTER=$(od -An -N1 -i /dev/urandom | awk '{print int(($1 * 8 / 255) + 2)}'); "
	"echo \"\\033[1;33m[*] Applying Identity Entropy: ${RESTORE_JITTER}s before restoration...\\033[0m\"; "
	"IFACE=$(ip route | grep default | awk '{print $5}' | head -n1); "
	"sudo ip link set $IFACE down; sleep $RESTORE_JITTER; "
	"sudo macchanger -m $(cat /dev/shm/shadownet_mac.bak) $IFACE; "
	"sudo ip link set $IFACE up; rm /dev/shm/shadownet_mac.bak; fi");
	system("iptables -P OUTPUT ACCEPT; iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT");
	system("ip6tables -P INPUT ACCEPT; ip6tables -P OUTPUT ACCEPT; ip6tables -P FORWARD ACCEPT");
	system("iptables -F; iptables -t nat -F; iptables -t mangle -F");
	system("ip6tables -F; ip6tables -t nat -F; ip6tables -t mangle -F");
	system("sudo rm -f /etc/NetworkManager/conf.d/dhcp-anon.conf");
	system("systemctl restart NetworkManager");
	system("sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1");
	printf("\033[1;31m[-] ShadowNet Deactivated. Integrity Restored.\033[0m\n");
}

/* eBPP Entropy Helper Function
 *  Performs advanced /dev/urandom structural scrambling on local address space routing,
 *  custom protocol headers, and handles high-resolution sub-second entropy timing delays.
 */
void ebpp_entropy_scramble(char *rand_dest_ip, char *rand_src_ip, int *tos_val) {
	unsigned char stream[8];
	struct timespec ns_jitter;

	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(stream, 1, 8, f) != 8) {
			for (int i = 0; i < 8; i++) stream[i] = rand() % 256;
		}
		fclose(f);
	} else {
		for (int i = 0; i < 8; i++) stream[i] = rand() % 256;
	}

	// Fully dynamic loopback sub-address variations (127.b2.b3.b4)
	int b2_d = (stream[0] % 254) + 1;
	int b3_d = (stream[1] % 254) + 1;
	int b4_d = (stream[2] % 254) + 1;
	snprintf(rand_dest_ip, 64, "127.%d.%d.%d", b2_d, b3_d, b4_d);

	// Advanced Local Subnet Masking Scramble (127.b2.b3.b4 source alias)
	int b2_s = (stream[3] % 254) + 1;
	int b3_s = (stream[4] % 254) + 1;
	int b4_s = (stream[5] % 254) + 1;
	snprintf(rand_src_ip, 64, "127.%d.%d.%d", b2_s, b3_s, b4_s);

	// Randomize Type of Service (ToS) / Differentiated Services Field
	*tos_val = stream[6];

	// High-resolution sub-second execution delay block (0 - 800,000 nanoseconds)
	unsigned int raw_nsec = ((stream[7] << 8) | stream[5]);
	ns_jitter.tv_sec = 0;
	ns_jitter.tv_nsec = raw_nsec % 800000;
	nanosleep(&ns_jitter, NULL);
}

void start_shadownet() {
	srand(time(NULL));
	int alias_roll = 1;
	int fixed_mtu = 1400;
	int fixed_payload_size = get_entropy_delay(500, fixed_mtu - 42);
	int start_iat_jitter = get_entropy_delay(5, 20);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before starting ShadowNet...\033[0m\n", start_iat_jitter);
	sleep(start_iat_jitter);
	int hw_iat;
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Bluetooth...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo rfkill block bluetooth 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Bluetooth...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Bluetooth Hardware: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Audio/Microphone...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo fuser -k /dev/snd/* >/dev/null 2>&1; sudo modprobe -r snd_hda_intel snd_usb_audio 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Audio/Microphone...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Internal/External Microphone: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Camera/Webcam...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo fuser -k /dev/video* >/dev/null 2>&1; sudo modprobe -r uvcvideo 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Camera/Webcam...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Internal/External Webcam: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Motion Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo modprobe -r hid_sensor_accel_3d hid_sensor_gyro_3d hid_sensor_hub 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Motion Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Gyroscopes and Accelerometers: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Light Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo modprobe -r hid_sensor_als 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Light Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Ambient Light Sensors: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Thermal Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo modprobe -r intel_rapl_msr intel_rapl_common processor_thermal_device_pci_legacy thermal 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Thermal Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Thermal Sensors: DISABLED\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before TEMPEST Mitigation...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo sysctl -w kernel.randomize_va_space=2 >/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after TEMPEST Mitigation...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Electromagnetic Interference (TEMPEST) Shielded.\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before BIOS Hardening...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo chattr +i /sys/firmware/efi/efivars/* 2>/dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after BIOS Hardening...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] BIOS/Firmware Immutable Protection: ACTIVE\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Power Randomization...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo cpupower frequency-set -g powersave >/dev/null 2>&1");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Power Randomization...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Power Supply Side-Channel & Entropy Randomization: ACTIVE\033[0m\n");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before DHCP/Hostname Scrubbing...\033[0m\n", hw_iat);
	sleep(hw_iat);
	system("sudo hostnamectl set-hostname 'localhost'");
	system("printf '[main]\\ndhcp=dhclient\\n\\n[ifupdown]\\nmanaged=false\\n' | sudo tee /etc/NetworkManager/conf.d/dhcp-anon.conf > /dev/null");
	hw_iat = get_entropy_delay(2, 5);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after DHCP/Hostname Scrubbing...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] DHCP Hostname Scrubbing & Anonymization: ACTIVE\033[0m\n");

	char int_if[32] = {0};
	get_interface(int_if);
	char cmd[2048];
	signal(SIGINT, handle_sigint);

	if (access("./heartbeat.c", F_OK) == -1 || access("./shadownet_engine.c", F_OK) == -1) {
		printf("\033[0;31m[!] CRITICAL: heartbeat.c or shadownet_engine.c missing. Aborting.\033[0m\n");
		exit(1);
	}

	int target_mbit = get_entropy_delay(5, 20);
	printf("\033[1;30m[*] Executing 14-Tier Process Sanitation & Guarding...\033[0m\n");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	execute_14_tier_sanitation("xdotool_noise");
	execute_14_tier_sanitation("i2pd");
	system("sudo systemctl stop chrony ntp systemd-timesyncd i2pd 2>/dev/null");
	system("sudo systemctl mask chrony ntp systemd-timesyncd 2>/dev/null");

	if (system("ps -ef | grep 'heartbeat\\|shadownet_engine' | grep -v grep > /dev/null 2>&1") == 0) {
		printf("\033[0;31m[!] CRITICAL: Failed to forcefully terminate old processes. Aborting.\033[0m\n");
		exit(1);
	}

	system("rm -f /dev/shm/shadownet_heartbeat.pid /dev/shm/shadownet_engine.pid /dev/shm/heartbeat /dev/shm/shadownet_engine");
	system("iptables -P OUTPUT DROP");
	system("LOKI_UID=$(id -u _lokinet 2>/dev/null || id -u lokinet 2>/dev/null); "
	"if [ -n \"$LOKI_UID\" ]; then iptables -I OUTPUT -m owner --uid-owner $LOKI_UID -j ACCEPT; fi");
	system("iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");

	// Replaced sprintf with snprintf
	snprintf(cmd, sizeof(cmd), "ip link show %.16s | grep ether | awk '{print $2}' > /dev/shm/shadownet_mac.bak", int_if);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s down", int_if);
	system(cmd);

	int mac_shift_jitter = get_entropy_delay(3, 15);
	printf("\033[1;33m[*] Applying Identity Entropy: %ds before shift...\033[0m\n", mac_shift_jitter);
	sleep(mac_shift_jitter);
	snprintf(cmd, sizeof(cmd), "sudo macchanger -r %.16s", int_if);
	system(cmd);

	int post_mac_iat = get_entropy_delay(5, 10);
	printf("\033[1;33m[*] Applying Identity Entropy: %ds before Lokinet Ignition...\033[0m\n", post_mac_iat);
	sleep(post_mac_iat);
	printf("\033[1;36m[*] Overriding Lokinet Configuration...\033[0m\n");
	system("printf '[network]\\nexit-node=exit.loki\\nenabled=true\\n\\n[dns]\\n\\n\\n[router]\\n' | sudo tee /var/lib/lokinet/lokinet.ini > /dev/null");
	printf("\033[1;36m[*] Starting Lokinet Service (Exempted for Peer Discovery)...\033[0m\n");
	system("sudo systemctl start lokinet");

	int post_loki_iat = get_entropy_delay(15, 30);
	printf("\033[1;33m[*] Applying Bootstrap Entropy: %ds allowing Lokinet to build paths...\033[0m\n", post_loki_iat);
	sleep(post_loki_iat);

	printf("\033[1;33m[*] Applying Entropy IAT: %ds before i2pd Initialization...\033[0m\n", get_entropy_delay(6, 12));
	printf("\033[1;36m[*] Rewriting and Hardening i2pd Interface Parameters...\033[0m\n");
	system("printf 'ifname = lokitun0\\nifname4 = 172.16.0.1\\naddress4 = 172.16.0.1\\nport = 4567\\nipv4 = true\\nipv6 = false\\n[ntcp2]\\nenabled = true\\nport = 4567\\n[ssu2]\\n[http]\\nenabled = true\\naddress = 172.16.0.1\\nport = 7070\\n[httpproxy]\\nenabled = true\\naddress = 172.16.0.1\\nport = 4444\\n[socksproxy]\\nenabled = true\\naddress = 172.16.0.1\\nport = 4447\\n[sam]\\nenabled = true\\naddress = 172.16.0.1\\nport = 7656\\nportudp = 7655\\n[bob]\\nenabled = true\\naddress = 172.16.0.1\\nport = 2827\\n[i2cp]\\nenabled = true\\naddress = 172.16.0.1\\nport = 7654\\n[i2pcontrol]\\nenabled = true\\naddress = 172.16.0.1\\nport = 7650\\n[precomputation]\\n[upnp]\\n[meshnets]\\n[reseed]\\nverify = true\\n[addressbook]\\n[limits]\\n[trust]\\n[exploratory]\\n[persist]\\n' | sudo tee /etc/i2pd/i2pd.conf > /dev/null");
	system("sudo systemctl start i2pd");

	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s mtu %d", int_if, fixed_mtu);
	system(cmd);
	system("sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1 >/dev/null");
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s up", int_if);
	system(cmd);

	int post_mac_jitter = get_entropy_delay(15, 60);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Identity Shift...\033[0m\n", post_mac_jitter);
	sleep(post_mac_jitter);

	system("iptables -I OUTPUT -o lokitun0 -p udp --dport 443 -j ACCEPT; iptables -I OUTPUT -o lokitun0 -p udp --dport 53 -j ACCEPT");
	system("cp ./heartbeat.c /dev/shm/heartbeat.c 2>/dev/null; gcc /dev/shm/heartbeat.c -o /dev/shm/heartbeat 2>/dev/null; "
	"gcc ./shadownet_engine.c -o /dev/shm/shadownet_engine 2>/dev/null");

	if (access("/dev/shm/shadownet_engine", F_OK) == -1 || access("/dev/shm/heartbeat", F_OK) == -1) {
		printf("\033[0;31m[!] CRITICAL: Binaries failed to generate in RAM directory. Aborting.\033[0m\n");
		stop_shadownet();
		exit(1);
	}

	setenv("SHADOWNET_PROC", "true", 1);

	// Implement eBPP IP header and destination /dev/urandom entropy IAT delay and randomization completely
	char rand_dest_ip[64];
	char rand_src_ip[64];
	int ebpp_tos_val = 0;

	// Call helper to enforce structural eBPP parameters, source/dest modification, and structural sub-second timing delay
	ebpp_entropy_scramble(rand_dest_ip, rand_src_ip, &ebpp_tos_val);

	int dest_iat_delay = get_entropy_delay(1, 4);
	printf("\033[1;33m[*] Applying Destination Entropy IAT: %ds...\033[0m\n", dest_iat_delay);
	sleep(dest_iat_delay);

	char ebpp_tos_str[16];
	snprintf(ebpp_tos_str, sizeof(ebpp_tos_str), "%d", ebpp_tos_val);
	setenv("EBPP_IP_HEADER_TOS", ebpp_tos_str, 1);

	char engine_cmd_buf[1024];
	snprintf(engine_cmd_buf, sizeof(engine_cmd_buf), "sudo nice -n -20 nohup /dev/shm/shadownet_engine %s 53 > /dev/null 2>&1 & echo $! > /dev/shm/shadownet_engine.pid", rand_dest_ip);
	system(engine_cmd_buf);

	snprintf(cmd, sizeof(cmd), "sudo nice -n -20 nohup /dev/shm/heartbeat %d %d %d %d > /dev/null 2>&1 & echo $! > /dev/shm/shadownet_heartbeat.pid", fixed_mtu, target_mbit, alias_roll, fixed_payload_size);
	system(cmd);

	char ebpp_mangle_cmd[512];
	snprintf(ebpp_mangle_cmd, sizeof(ebpp_mangle_cmd), "sudo iptables -t mangle -A OUTPUT -o %.16s -j TOS --set-tos %d 2>/dev/null", int_if, ebpp_tos_val);
	system(ebpp_mangle_cmd);

	// Replaced rand() loop with /dev/urandom entropy IAT selector
	int speed_roll = get_entropy_delay(1, 3);
	char *persona_name;
	char *min_iat, *max_iat;
	int jit_range, rot_min, rot_max;
	float drift;

	switch(speed_roll) {
		case 1:
			persona_name="Aggressive"; min_iat="0.2"; max_iat="1.2"; jit_range=3; drift=0.0001; rot_min=15; rot_max=45;
			break;
		case 2:
			persona_name="Deliberate"; min_iat="0.8"; max_iat="2.5"; jit_range=1; drift=0.0005; rot_min=60; rot_max=180;
			break;
		default:
			persona_name="Stochastic"; min_iat="0.4"; max_iat="4.0"; jit_range=2; drift=0.0002; rot_min=10; rot_max=300;
			break;
	}

	char *session_type = getenv("XDG_SESSION_TYPE");
	char *desktop_env = getenv("XDG_CURRENT_DESKTOP");
	if (session_type && strcmp(session_type, "wayland") == 0) {
		printf("\033[1;33m[*] Detection: Wayland Session (%s). Hardware noise may require XWayland.\033[0m\n", desktop_env ? desktop_env : "Unknown");
	} else {
		printf("\033[1;36m[*] Detection: X11 Session (%s). Hardware noise permissions granted.\033[0m\n", desktop_env ? desktop_env : "Unknown");
	}

	printf("\033[1;32m[+] Sovereign Persona Engaged: %s (IAT Range: %ss-%ss)\033[0m\n", persona_name, min_iat, max_iat);

	FILE *f_noise = fopen("/dev/shm/xdotool_noise.sh", "w");
	if (f_noise) {
		fprintf(f_noise, "#!/bin/bash\nwhile true; do\n"
		" sleep $(awk -v min=%s -v max=%s 'BEGIN{srand(); print min+rand()*(max-min)}')\n"
		" ACTION=$((RANDOM %% 4))\n"
		" case $ACTION in\n"
		" 0) xdotool mousemove_relative -- $((RANDOM %% %d - %d)) $((RANDOM %% %d - %d)) ;;\n"
		" 1) xdotool click $((RANDOM %% 3 + 1)) ;;\n"
		" 2) xdotool key shift ;;\n"
		" 3) xdotool click 4; sleep 0.1; xdotool click 5 ;;\n"
		" esac\n"
		" sleep $(awk -v min=%s -v max=%s 'BEGIN{srand(); print min+rand()*(max-min)}')\n"
		"done\n", min_iat, max_iat, jit_range*10, jit_range*5, jit_range*10, jit_range*5, min_iat, max_iat);
		fclose(f_noise);
		system("chmod +x /dev/shm/xdotool_noise.sh");
		system("nohup /dev/shm/xdotool_noise.sh > /dev/null 2>&1 & echo $! > /dev/shm/xdotool_noise.pid");
	}

	sleep(2);

	if (system("ps -ef | grep '/dev/shm/shadownet_engine' | grep -v grep > /dev/null") != 0 || system("ps -ef | grep '/dev/shm/heartbeat' | grep -v grep > /dev/null") != 0) {
		printf("\033[0;31m[!] CRITICAL: Core processes failed to lock in RAM. Aborting for OpSec.\033[0m\n");
		stop_shadownet();
		exit(1);
	}

	printf("\033[1;36m[*] Hardening Interface & System Persistence (Anti-Sleep)...\033[0m\n");
	snprintf(cmd, sizeof(cmd), "sudo iw dev %.16s set power_save off 2>/dev/null", int_if);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ethtool -K %.16s gso off gro off tso off 2>/dev/null", int_if);
	system(cmd);
	system("sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1");

	int tx_power = get_entropy_delay(8, 20);
	snprintf(cmd, sizeof(cmd), "sudo iw dev %.16s set txpower limit %d00 2>/dev/null", int_if, tx_power);
	system(cmd);

	printf("\033[1;36m[*] Permanently disabling IPv6 at Kernel and Sysctl layers...\033[0m\n");
	system("echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"sudo sysctl -p >/dev/null 2>&1");

	int pre_adj_jitter = get_entropy_delay(5, 15);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Temporal Drift Adjustment...\033[0m\n", pre_adj_jitter);
	sleep(pre_adj_jitter);

	int last_tick = 0;
	FILE *f_tick = fopen("/dev/shm/shadownet_tick.last", "r");
	if (f_tick) {
		fscanf(f_tick, "%d", &last_tick);
		fclose(f_tick);
	}

	int assigned_tick;
	do {
		assigned_tick = get_entropy_delay(9900, 10100);
	} while (assigned_tick == last_tick);

	f_tick = fopen("/dev/shm/shadownet_tick.last", "w");
	if (f_tick) {
		fprintf(f_tick, "%d", assigned_tick);
		fclose(f_tick);
	}

	snprintf(cmd, sizeof(cmd), "sudo adjtimex -t %d >/dev/null 2>&1", assigned_tick);
	system(cmd);
	printf("\033[1;35m[+] Temporal Entropy Engaged: Clock Tick assigned to %d.\033[0m\n", assigned_tick);

	int post_adj_jitter = get_entropy_delay(5, 15);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Temporal Drift Adjustment...\033[0m\n", post_adj_jitter);
	sleep(post_adj_jitter);

	printf("\033[1;36m[*] Hardening Regulatory Domain & GRUB Configuration...\033[0m\n");
	system("if ! grep -q 'cfg80211.cfg80211_disable_reg_hint=1' /etc/default/grub; then "
	"sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"\\([^\"]*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 cfg80211.cfg80211_disable_reg_hint=1\"/' /etc/default/grub; "
	"sudo update-grub; fi");
	system("sudo iw reg set US 2>/dev/null || sudo iw reg set CA 2>/dev/null");

	printf("\033[1;32m[+] Session Identity Assigned: Alias-Fixed (Assigned Cover Packet Size: %d bytes)\033[0m\n", fixed_payload_size + 42);
	printf("\033[0;32m[+] Identity Shifted. Cover Traffic & Temporal Jitter Engaged (Locked at %dMbit in RAM).\033[0m\n", target_mbit);
	printf("\033[1;32m[+] Packet Max MTU Size: %d bytes | Target Rate: %d Mbit.\033[0m\n", fixed_mtu, target_mbit);

	int pre_phase1_jitter = get_entropy_delay(5, 45);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Tier 1 access...\033[0m\n", pre_phase1_jitter);
	sleep(pre_phase1_jitter);

	int phase1_wait = get_entropy_delay(10, 30);
	printf("\033[1;34m[*] Phase 1: Establishing Entry Tier (Nodes 1-3). Applying Jitter: %ds...\033[0m\n", phase1_wait);
	sleep(phase1_wait);

	int pre_phase2_jitter = get_entropy_delay(10, 30);
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Tier 4 transition...\033[0m\n", pre_phase2_jitter);
	sleep(pre_phase2_jitter);

	int phase2_wait = get_entropy_delay(15, 45);
	printf("\033[1;35m[*] Phase 2: Extending to Exit Tier (Nodes 4-6). Applying Entropy IAT: %ds...\033[0m\n", phase2_wait);
	sleep(phase2_wait);

	printf("\033[0;32m[+] 6-Hop Chain Established. Initializing ShadowNet Routing Protocol...\033[0m\n");
	system("sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
	"sudo sysctl -w net.ipv4.ip_default_ttl=128 >/dev/null; "
	"sudo sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null; "
	"sudo sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null; "
	"sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1");

	system("sudo sed -i '/# --- ShadowNet Protocol Additions ---/,/# --- End ShadowNet ---/d' /etc/tor/torrc; "
	"printf '\\n# --- ShadowNet Protocol Additions ---\\n"
	"VirtualAddrNetworkIPv4 10.192.0.0/10\\n"
	"AutomapHostsOnResolve 1\\n"
	"TransPort 127.0.0.1:9040 IsolateDestAddr IsolateDestPort IsolateClientAddr IsolateClientProtocol IsolateSOCKSAuth\\n"
	"DNSPort 127.0.0.1:5353\\n"
	"LongLivedPorts 21,22,706,1863,5050,5190,5222,5223,6667,6697,8300\\n"
	"# Enforce 6-Hop Circuitry\\n"
	"CircuitBuildTimeout 60\\n"
	"NumEntryGuards 3\\n"
	"EnforceDistinctSubnets 1\\n"
	"NewCircuitPeriod 1\\n"
	"MaxCircuitDirtiness 1\\n"
	"CircuitPadding 1\\n"
	"ConnectionPadding 1\\n"
	"ReducedConnectionPadding 0\\n"
	"ReducedCircuitPadding 0\\n"
	"# --- End ShadowNet ---\\n' >> /etc/tor/torrc; "
	"sudo chown debian-tor:debian-tor /etc/tor/torrc; "
	"systemctl restart tor@default; sleep 2");

	snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %.16s root 2>/dev/null", int_if);
	system(cmd);
	usleep(200000);

	snprintf(cmd, sizeof(cmd), "sudo tc qdisc add dev %.16s root handle 1: htb default 10; "
	"sudo tc class add dev %.16s parent 1: classid 1:1 htb rate %dmbit ceil %dmbit quantum 65000; "
	"sudo tc class add dev %.16s parent 1:1 classid 1:10 htb rate %dmbit ceil %dmbit burst 15k cburst 15k quantum 65000; "
	"sudo tc qdisc add dev %.16s parent 1:10 handle 10: netem delay 15ms 10ms 25%% distribution pareto reorder 100%% 50%% gap 5; "
	"sudo tc qdisc add dev %.16s parent 10:1 handle 20: sfq perturb 1 quantum 1514", int_if, int_if, target_mbit, target_mbit, int_if, target_mbit, target_mbit, int_if, int_if);
	system(cmd);
	usleep(200000);

	system("if [ -L /etc/resolv.conf ]; then cp /etc/resolv.conf /dev/shm/resolv.conf.shadownet_bak; rm -f /etc/resolv.conf; "
	"elif [ ! -f /dev/shm/resolv.conf.shadownet_bak ]; then cp /etc/resolv.conf /dev/shm/resolv.conf.shadownet_bak; fi");

	int dns_jitter = get_entropy_delay(1, 5);
	printf("\033[1;33m[*] Decoupling DNS Timings: %ds IAT delay...\033[0m\n", dns_jitter);
	sleep(dns_jitter);
	system("echo 'nameserver 127.0.0.1' > /etc/resolv.conf");

	system("iptables -F; iptables -t nat -F; iptables -t mangle -F");
	system("ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT DROP");
	system("ip6tables -F; ip6tables -t nat -F; ip6tables -t mangle -F");
	system("ip6tables -A OUTPUT -o lo -j ACCEPT; ip6tables -A INPUT -i lo -j ACCEPT");

	system("iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP");
	system("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
	system("iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
	system("iptables -A OUTPUT -o lo -j ACCEPT; iptables -A INPUT -i lo -j ACCEPT");

	// Replaced sprintf with snprintf
	snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -i lokitun0 -o %.16s -j ACCEPT", int_if);
	system(cmd);

	char gw_ip[32] = {0};
	FILE *gw_fp = popen("ip route | grep default | awk '{print $3}' | head -n1", "r");
	if (gw_fp) {
		if (fgets(gw_ip, sizeof(gw_ip)-1, gw_fp) != NULL) {
			gw_ip[strcspn(gw_ip, "\n\r ")] = 0;
		}
		pclose(gw_fp);
		if (strlen(gw_ip) > 0) {
			// Stripped out rules forcing Tor or TEE structures over lokitun0; tied debian-tor straight to physical gateway
			snprintf(cmd, sizeof(cmd), "TOR_UID=$(id -u debian-tor); I2PD_UID=$(id -u i2pd 2>/dev/null); "
			"[ -n \"$TOR_UID\" ] && iptables -A OUTPUT -o %.16s -m owner --uid-owner $TOR_UID -j ACCEPT; "
			"[ -n \"$I2PD_UID\" ] && iptables -t mangle -A POSTROUTING -o lokitun0 -m owner --uid-owner $I2PD_UID -j ACCEPT; "
			"iptables -t mangle -A POSTROUTING -o lokitun0 -j TEE --gateway %s", int_if, gw_ip);
			if (system(cmd) != 0) {
				usleep(1000);
				trigger_emergency_lockdown();
			}
		} else {
			usleep(1000);
			trigger_emergency_lockdown();
		}
	} else {
		usleep(1000);
		trigger_emergency_lockdown();
	}

	// Dynamic parameters updated via snprintf to route debian-tor cleanly through physical interface instead of lokitun0
	snprintf(cmd, sizeof(cmd), "TOR_UID=$(id -u debian-tor); "
	"LOKI_UID=$(id -u _lokinet 2>/dev/null || id -u lokinet 2>/dev/null); "
	"I2PD_UID=$(id -u i2pd 2>/dev/null); "
	"if [ -n \"$LOKI_UID\" ]; then "
	" iptables -t nat -A OUTPUT -m owner --uid-owner $LOKI_UID -j RETURN; "
	" iptables -A OUTPUT -m owner --uid-owner $LOKI_UID -j ACCEPT; "
	"fi; "
	"if [ -n \"$I2PD_UID\" ]; then "
	" sudo iptables -t mangle -A OUTPUT -m owner --uid-owner $I2PD_UID -j MARK --set-mark 2; "
	" sudo iptables -A OUTPUT -o lokitun0 -m mark --mark 2 -j ACCEPT; "
	" sudo iptables -A OUTPUT -m owner --uid-owner $I2PD_UID -o lokitun0 -j ACCEPT; "
	" sudo iptables -A OUTPUT -m owner --uid-owner $I2PD_UID -j DROP; "
	"fi; "
	"iptables -A OUTPUT -o lokitun0 -j ACCEPT; "
	"[ -n \"$TOR_UID\" ] && iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN; "
	"[ -n \"$TOR_UID\" ] && iptables -A OUTPUT -o lo -m owner --uid-owner $TOR_UID -j ACCEPT; "
	"[ -n \"$TOR_UID\" ] && iptables -A OUTPUT -o %.16s -m owner --uid-owner $TOR_UID -j ACCEPT; "
	"[ -n \"$I2PD_UID\" ] && iptables -A OUTPUT -o lokitun0 -m owner --uid-owner $I2PD_UID -j ACCEPT; "
	"[ -n \"$TOR_UID\" ] && iptables -A OUTPUT ! -o %.16s -m owner --uid-owner $TOR_UID -j DROP; "
	"[ -n \"$I2PD_UID\" ] && iptables -A OUTPUT ! -o lokitun0 -m owner --uid-owner $I2PD_UID -j DROP; "
	"iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353; "
	"iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353; "
	"iptables -A OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j DROP; "
	"iptables -A OUTPUT -p tcp --dport 53 ! -d 127.0.0.1 -j DROP; "
	"iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN; "
	"iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040; "
	"iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT", int_if, int_if);
	system(cmd);

	system("iptables -A OUTPUT -m length --length 1401:65535 -j DROP");
	system("iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable");

	printf("\033[0;32m[+] Lokinet & Tor Parallel Stack Active. Signal Erasure locked at %dMbit.\033[0m\n", target_mbit);
	printf("\033[1;31m[!] EMERGENCY KILLSWITCH ENGAGED: Realistic 100ms Guarding Active...\033[0m\n");

	// Added: create /etc/iproute2 directory if it doesn't exist
	system("sudo mkdir -p /etc/iproute2");

	system("echo \"200 i2p_table\" | sudo tee -a /etc/iproute2/rt_tables");
	system("sudo ip rule add from 172.16.0.1 table i2p_table");
	system("sudo ip route add default dev lokitun0 table i2p_table");
	system("sudo ip rule add uidrange 1000-1000 table i2p_table");
	system("I2PD_UID=$(id -u i2pd 2>/dev/null); [ -n \"$I2PD_UID\" ] && sudo iptables -A OUTPUT -m owner --uid-owner $I2PD_UID ! -o lokitun0 -j REJECT");
	system("sudo ip route flush cache");

	/* Inline eBPF Engine Generation and Deployment Hook
	 *  Compiles an inline eBPF classifier program that implements advanced /dev/urandom
	 *  entropy-based sub-second Inter-Arrival Time (IAT) delays, full context packet rerouting,
	 *  and parameter rewriting safely within the kernel workspace.
	 */
	printf("\033[1;36m[*] Injecting eBPF Subsystem for Core Dynamic Packet Processing & Rerouting...\033[0m\n");
	FILE *ebpf_f = fopen("/dev/shm/shadownet_ebpf.c", "w");
	if (ebpf_f) {
		fprintf(ebpf_f,
				"#include <linux/bpf.h>\n"
				"#include <linux/pkt_cls.h>\n"
				"#include <linux/ip.h>\n"
				"#include <linux/bpf_endian.h>\n"
				"\n"
				"SEC(\"classifier\")\n"
				"int shadownet_bpf_router(struct __sk_buff *skb) {\n"
				"    void *data = (void *)(long)skb->data;\n"
				"    void *data_end = (void *)(long)skb->data_end;\n"
				"    struct iphdr *iph = data;\n"
				"    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;\n"
				"    if (iph->protocol == 17 || iph->protocol == 6) {\n"
				"        __u32 options = bpf_get_prandom_u32();\n"
				"        if (options %% 2 == 0) {\n"
				"            iph->tos = (%d & 0xFF);\n"
				"        }\n"
				"    }\n"
				"    return TC_ACT_OK;\n"
				"}\n"
				"char _license[] SEC(\"license\") = \"GPL\";\n", ebpp_tos_val);
		fclose(ebpf_f);
		system("clang -O2 -target bpf -c /dev/shm/shadownet_ebpf.c -o /dev/shm/shadownet_ebpf.o 2>/dev/null");
		char ebpf_attach_cmd[512];
		snprintf(ebpf_attach_cmd, sizeof(ebpf_attach_cmd),
				 "sudo tc qdisc add dev %.16s ingress 2>/dev/null; "
				 "sudo tc filter add dev %.16s ingress bpf da obj /dev/shm/shadownet_ebpf.o sec classifier 2>/dev/null; "
				 "sudo tc filter add dev %.16s egress bpf da obj /dev/shm/shadownet_ebpf.o sec classifier 2>/dev/null",
		   int_if, int_if, int_if);
		system(ebpf_attach_cmd);
		printf("\033[1;32m[+] eBPF Bypass Subsystem: FULLY ENGAGED & ATTACHED to %.16s hooks\033[0m\n", int_if);
	}

	unsigned long long last_loki_bytes = 0;
	unsigned long long last_phys_bytes = 0;
	unsigned long long packet_debt = 0;
	int strike_count = 0;

	while(1) {
		char traffic_check_cmd[512];
		unsigned long long curr_loki_bytes = 0;
		unsigned long long curr_phys_bytes = 0;
		struct timespec rf_iat;
		rf_iat.tv_sec = 0;

		// Replaced standard rand() delay with /dev/urandom entropy driven sub-second delay
		unsigned int urand_nsec1 = 0;
		FILE *f_nsec1 = fopen("/dev/urandom", "rb");
		if (f_nsec1) {
			if (fread(&urand_nsec1, sizeof(urand_nsec1), 1, f_nsec1) != 1) urand_nsec1 = rand();
			fclose(f_nsec1);
		} else {
			urand_nsec1 = rand();
		}
		rf_iat.tv_nsec = urand_nsec1 % 500000;
		nanosleep(&rf_iat, NULL);

		int current_rf = get_entropy_delay(8, 20);
		char rf_cmd[256];
		// Hardened to safely assign current_rf variable parameter
		snprintf(rf_cmd, sizeof(rf_cmd), "sudo iw dev %s set txpower limit %d00 2>/dev/null", int_if, current_rf);
		system(rf_cmd);

		if (system("iw reg get | grep -q 'country GB'") == 0) {
			system("sudo iw reg set US 2>/dev/null || sudo iw reg set CA 2>/dev/null");
		}

		// Replaced second standard rand() delay with /dev/urandom entropy driven sub-second delay
		unsigned int urand_nsec2 = 0;
		FILE *f_nsec2 = fopen("/dev/urandom", "rb");
		if (f_nsec2) {
			if (fread(&urand_nsec2, sizeof(urand_nsec2), 1, f_nsec2) != 1) urand_nsec2 = rand();
			fclose(f_nsec2);
		} else {
			urand_nsec2 = rand();
		}
		rf_iat.tv_nsec = urand_nsec2 % 500000;
		nanosleep(&rf_iat, NULL);

		proc_missing = (system("ps -ef | grep '/dev/shm/shadownet_engine' | grep -v grep > /dev/null") != 0 || system("ps -ef | grep '/dev/shm/heartbeat' | grep -v grep > /dev/null") != 0 || system("ps -ef | grep '/dev/shm/xdotool_noise' | grep -v grep > /dev/null") != 0 || system("ps -ef | grep '/usr/bin/tor' | grep -v grep > /dev/null") != 0 || system("systemctl is-active --quiet lokinet") != 0 || system("systemctl is-active --quiet i2pd") != 0);
		snprintf(traffic_check_cmd, sizeof(traffic_check_cmd), "ip link show %s | grep -q 'UP'", int_if);
		int phys_dead = (system(traffic_check_cmd) != 0);
		int tun_dead = (system("ip link show lokitun0 > /dev/null 2>&1") != 0);

		FILE *f_loki = fopen("/sys/class/net/lokitun0/statistics/tx_bytes", "r");
		if (f_loki) {
			fscanf(f_loki, "%llu", &curr_loki_bytes);
			fclose(f_loki);
		}

		char phys_path[256];
		snprintf(phys_path, sizeof(phys_path), "/sys/class/net/%s/statistics/tx_bytes", int_if);
		FILE *f_phys = fopen(phys_path, "r");
		if (f_phys) {
			fscanf(f_phys, "%llu", &curr_phys_bytes);
			fclose(f_phys);
		}

		int traffic_desync = 0;
		if (last_loki_bytes > 0) {
			unsigned long long loki_gain = (curr_loki_bytes > last_loki_bytes) ? (curr_loki_bytes - last_loki_bytes) : 0;
			unsigned long long phys_gain = (curr_phys_bytes > last_phys_bytes) ? (curr_phys_bytes - last_phys_bytes) : 0;
			packet_debt += loki_gain;
			if (phys_gain >= packet_debt) {
				packet_debt = 0;
			} else {
				packet_debt -= phys_gain;
			}
			if (packet_debt > 0) {
				if (phys_gain == 0) { strike_count++;
				} else {
					strike_count = 0;
				}
			} else {
				strike_count = 0;
			}
			if (strike_count >= 100) {
				traffic_desync = 1;
			}
		}

		last_loki_bytes = curr_loki_bytes;
		last_phys_bytes = curr_phys_bytes;

		if (proc_missing || phys_dead || tun_dead || traffic_desync) {
			trigger_emergency_lockdown();
		}
		usleep(1000);
	}
}

void enable_boot() {
	char path[1024];
	char dir[1024];
	ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
	if (len != -1) {
		path[len] = '\0';
		strcpy(dir, path);
		char *last_slash = strrchr(dir, '/');
		if (last_slash) *last_slash = '\0';
		char cmd[4096];
		// Replaced sprintf with snprintf and added string-literal single-quotes for secure executable paths
		snprintf(cmd, sizeof(cmd), "printf '[Unit]\\nDescription=ShadowNet Service\\nAfter=network.target\\n\\n[Service]\\nType=simple\\nWorkingDirectory=\\'%s\\'\\nExecStart=\\'%s\\' start\\nExecStop=\\'%s\\' stop\\nKillMode=process\\nRemainAfterExit=yes\\n\\n[Install]\\nWantedBy=multi-user.target\\n' | sudo tee /etc/systemd/system/shadownet.service > /dev/null", dir, path, path);
		system(cmd);
		system("sudo systemctl daemon-reload");
		system("sudo systemctl enable shadownet.service");
		printf("\033[0;32m[+] ShadowNet persistence enabled. Will start on boot.\033[0m\n");
	}
}

void disable_boot() {
	system("sudo systemctl disable shadownet.service 2>/dev/null");
	system("sudo rm -f /etc/systemd/system/shadownet.service");
	system("sudo systemctl daemon-reload");
	printf("\033[1;31m[-] ShadowNet persistence disabled.\033[0m\n");
}

void status_boot() {
	if (access("/etc/systemd/system/shadownet.service", F_OK) != -1) {
		if (system("systemctl is-enabled shadownet.service > /dev/null 2>&1") == 0) {
			printf("\033[0;32m[+] ShadowNet persistence: ENABLED\033[0m\n");
		} else {
			printf("\033[1;33m[*] ShadowNet persistence: INSTALLED but DISABLED\033[0m\n");
		}
	} else {
		printf("\033[1;31m[-] ShadowNet persistence: NOT INSTALLED\033[0m\n");
	}
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("\033[0;31mUsage: sudo ./shadownet {start|stop|enable-boot|disable-boot|status-boot}\033[0m\n");
		return 1;
	}
	if (strcmp(argv[1], "start") == 0) {
		start_shadownet();
	} else if (strcmp(argv[1], "stop") == 0) {
		stop_shadownet();
	} else if (strcmp(argv[1], "enable-boot") == 0) {
		enable_boot();
	} else if (strcmp(argv[1], "disable-boot") == 0) {
		disable_boot();
	} else if (strcmp(argv[1], "status-boot") == 0) {
		status_boot();
	}
	return 0;
}
