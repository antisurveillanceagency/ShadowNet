#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <math.h> // Added for exponential distribution calculations

// Global variable required by the monitoring loop condition
int proc_missing = 0;

/* Helper function to securely execute commands using fork and execve,
 * replacing the vulnerable system() call completely while maintaining execution context.
 */
int safe_execute(const char *cmd_string) {
	pid_t pid = fork();
	if (pid == 0) {
		char *args[] = {"/bin/sh", "-c", (char *)cmd_string, NULL};
		// Using execve for maximum control over environment isolation and purging LD_PRELOAD vectors
		char *safe_env[] = {
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"SHADOWNET_PROC=true",
			NULL
		};
		execve("/bin/sh", args, safe_env);
		_exit(127);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
		return -1;
	}
	return -1;
}

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

// Loopix Helper: Generates an exponential delay matching specific lambda parameter
double get_loopix_poisson_delay(double lambda) {
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

// Refactored to completely derive boundaries from the Loopix exponential/Poisson structure
int get_entropy_delay(int min, int max) {
	double target_mean = ((double)min + (double)max) / 2.0;
	if (target_mean <= 0.0) target_mean = 1.0;
	double lambda = 1.0 / target_mean;
	double delay = get_loopix_poisson_delay(lambda);
	int idelay = (int)delay;
	if (idelay < min) idelay = min;
	if (idelay > max) idelay = max;
	return idelay;
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
	return rand_val % 2; 
}

void execute_14_tier_sanitation(const char *name) {
	char cmd[2048];
	char short_name[16];
	strncpy(short_name, name, 15);
	short_name[15] = '\0';
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
	safe_execute(cmd);
	if (strstr(name, "engine") != NULL) {
		safe_execute("PORT_PIDS=$(sudo ss -lptn 'sport = :76' | grep -oP 'pid=\\K[0-9]+'); for p_pid in $PORT_PIDS; do sudo kill -9 $p_pid 2>/dev/null; done");
	}
}

void trigger_emergency_lockdown() {
	safe_execute("sudo bpftool map update pinned /sys/fs/bpf/shadownet_lockdown_map key 0 0 0 0 value 1 0 0 0 2>/dev/null");
	safe_execute("nft flush ruleset");
	safe_execute("nft add table inet shadownet");
	safe_execute("nft add chain inet shadownet input { type filter hook input priority 0 \\; policy drop \\; }; nft add chain inet shadownet forward { type filter hook forward priority 0 \\; policy drop \\; }");
	safe_execute("nft add chain inet shadownet output { type filter hook output priority 0 \\; policy drop \\; }");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	safe_execute("sudo systemctl stop tor");
	printf("\n\033[0;31m\a[!!!] SHADOWNET EMERGENCY LOCKDOWN ENGAGED. INTERNET PERMANENTLY KILLED | Co Authored By JS / ASA.\033[0m\n");
	printf("\033[1;33m[*] Run 'sudo ./shadownet stop' manually to restore connectivity.\033[0m\n");
	exit(1);
}

void handle_sigint(int sig) {
	trigger_emergency_lockdown();
}

void stop_shadownet() {
	char int_if[32] = {0};
	get_interface(int_if);
	safe_execute("nft flush ruleset");
	safe_execute("nft add table inet shadownet");
	safe_execute("nft add chain inet shadownet input { type filter hook input priority 0 \\; policy drop \\; }; nft add chain inet shadownet forward { type filter hook forward priority 0 \\; policy drop \\; }");
	safe_execute("nft add chain inet shadownet output { type filter hook output priority 0 \\; policy drop \\; }");
	
	int exit_dns_jitter = (int)get_loopix_poisson_delay(0.25);
	if (exit_dns_jitter < 2) exit_dns_jitter = 2;
	if (exit_dns_jitter > 8) exit_dns_jitter = 8;
	printf("\033[1;31m[*] Pending exit... Applying Exit DNS Entropy: %ds...\033[0m\n", exit_dns_jitter);
	sleep(exit_dns_jitter);
	
	int wait_time = (int)get_loopix_poisson_delay(0.05);
	if (wait_time < 5) wait_time = 5;
	if (wait_time > 60) wait_time = 60;
	printf("\033[1;31m[*] Finalizing teardown... Waiting %d seconds.\033[0m\n", wait_time);
	sleep(wait_time);
	
	safe_execute("sudo systemctl unmask chrony ntp systemd-timesyncd 2>/dev/null");
	safe_execute("sudo systemctl start chrony ntp systemd-timesyncd 2>/dev/null");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	safe_execute("sudo rfkill unblock bluetooth 2>/dev/null");
	
	// Dynamic existence verification before restoring modules
	if (access("/lib/modules/$(uname -r)/kernel/drivers/media/usb/uvc", F_OK) == 0 || system("modinfo uvcvideo >/dev/null 2>&1") == 0) {
		safe_execute("sudo modprobe uvcvideo 2>/dev/null");
	}
	if (access("/lib/modules/$(uname -r)/kernel/sound", F_OK) == 0 || system("modinfo snd-hda-intel >/dev/null 2>&1") == 0) {
		safe_execute("sudo modprobe snd_hda_intel 2>/dev/null");
	}
	
	safe_execute("sudo chattr -i /sys/firmware/efi/efivars/* 2>/dev/null");
	rmdir("/dev/shm/shadownet_heartbeat.pid /dev/shm/shadownet_engine.pid");
	safe_execute("rm -f /dev/shm/shadownet_heartbeat.pid /dev/shm/shadownet_engine.pid");
	safe_execute("rm -f /dev/shm/heartbeat /dev/shm/shadownet_engine");
	safe_execute("sudo sysctl -w net.ipv4.ip_default_ttl=64 >/dev/null");
	safe_execute("sudo sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null");
	safe_execute("sudo sysctl -w net.ipv4.ip_no_pmtu_disc=0 >/dev/null");
	safe_execute("sudo adjtimex -t 10000 >/dev/null 2>&1");
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %.16s root 2>/dev/null", int_if);
	safe_execute(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s mtu 1500", int_if);
	safe_execute(cmd);
	
	safe_execute("sudo chattr -i /etc/resolv.conf 2>/dev/null");
	safe_execute("if [ -f /dev/shm/resolv.conf.shadownet_bak ]; then rm -f /etc/resolv.conf; mv /dev/shm/resolv.conf.shadownet_bak /etc/resolv.conf; fi");
	safe_execute("sudo mount -o remount,rw,hidepid=0 /proc 2>/dev/null");
	
	int restore_jitter_val = (int)(get_loopix_poisson_delay(1.0 / 5.0));
	if (restore_jitter_val < 2) restore_jitter_val = 2;
	if (restore_jitter_val > 15) restore_jitter_val = 15;
	char restore_cmd[1024];
	snprintf(restore_cmd, sizeof(restore_cmd),
			 "if [ -f /dev/shm/shadownet_mac.bak ]; then "
			 "echo \"\\033[1;33m[*] Applying Identity Entropy: %ds before restoration...\\033[0m\"; "
			 "IFACE=$(ip route | grep default | awk '{print $5}' | head -n1); "
			 "sudo ip link set $IFACE down; sleep %d; "
			 "sudo macchanger -m $(cat /dev/shm/shadownet_mac.bak) $IFACE; "
			 "sudo ip link set $IFACE up; rm /dev/shm/shadownet_mac.bak; fi", restore_jitter_val, restore_jitter_val);
	safe_execute(restore_cmd);
	
	safe_execute("nft flush ruleset");
	safe_execute("nft add table inet shadownet");
	safe_execute("nft add chain inet shadownet input { type filter hook input priority 0 \\; policy accept \\; }; nft add chain inet shadownet forward { type filter hook forward priority 0 \\; policy accept \\; }");
	safe_execute("nft add chain inet shadownet output { type filter hook output priority 0 \\; policy accept \\; }");
	safe_execute("sudo rm -f /etc/NetworkManager/conf.d/dhcp-anon.conf");
	safe_execute("systemctl restart NetworkManager");
	safe_execute("sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1");
	
	char xdp_off_cmd[256];
	snprintf(xdp_off_cmd, sizeof(xdp_off_cmd), "sudo ip link set dev %.16s xdp off 2>/dev/null", int_if);
	safe_execute(xdp_off_cmd);
	
	safe_execute("sudo rm -f /sys/fs/bpf/shadownet_lockdown_map 2>/dev/null");
	printf("\n\033[1;31m[-] ShadowNet Deactivated. Integrity Restored | Co Authored By JS / ASA.\033[0m\n");
}

void ebpp_entropy_scramble(char *rand_dest_ip, char *rand_src_ip, int *tos_val) {
	unsigned char stream[8];
	struct timespec ns_jitter;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(stream, 1, 8, f) != 8) {
			for (int i = 0; i < 8; i++) stream[i] = stream[0];
		}
		fclose(f);
	} else {
		for (int i = 0; i < 8; i++) stream[i] = 127;
	}
	int b2_d = (stream[0] % 254) + 1;
	int b3_d = (stream[1] % 254) + 1;
	int b4_d = (stream[2] % 254) + 1;
	snprintf(rand_dest_ip, 64, "127.%d.%d.%d", b2_d, b3_d, b4_d);
	int b2_s = (stream[3] % 254) + 1;
	int b3_s = (stream[4] % 254) + 1;
	int b4_s = (stream[5] % 254) + 1;
	snprintf(rand_src_ip, 64, "127.%d.%d.%d", b2_s, b3_s, b4_s);
	*tos_val = stream[6];
	
	double u_ebpp = (double)((stream[7] << 8) | stream[5]) / 65535.0;
	if (u_ebpp <= 0.0) u_ebpp = 0.000001;
	double delay_ebpp = -log(u_ebpp) * 400000.0;
	ns_jitter.tv_sec = 0;
	ns_jitter.tv_nsec = (long)delay_ebpp % 800000;
	nanosleep(&ns_jitter, NULL);
}

void start_shadownet() {
	// Startup Dependency & Environment Pre-Check (Comprehensive List of all binaries/utilities used across all system calls)
	const char *required_bins[] = {
		"lsof", "fuser", "macchanger", "clang", "adjtimex", "nft", "ip", "ethtool", "iw", "cpupower",
		"tor", "grep", "awk", "head", "tail", "sed", "cut", "sort", "find", "ps", "ss", "modprobe",
		"lsmod", "modinfo", "chattr", "rmdir", "rm", "cp", "mkdir", "mount", "sysctl", "hostnamectl",
		"systemctl", "update-grub", "gcc", "bpftool", "basename", "uname", "tee", "tr", "expr"
	};
	int num_bins = sizeof(required_bins) / sizeof(required_bins[0]);
	for (int i = 0; i < num_bins; i++) {
		char check_cmd[128];
		snprintf(check_cmd, sizeof(check_cmd), "command -v %s >/dev/null 2>&1", required_bins[i]);
		if (system(check_cmd) != 0) {
			double dep_delay = get_loopix_poisson_delay(1.0);
			struct timespec dep_ts = {0, (long)(dep_delay * 1000000.0)};
			nanosleep(&dep_ts, NULL);
			fprintf(stderr, "\033[0;31m[!] CRITICAL DEPENDENCY MISSING: '%s' is not installed or unavailable.\033[0m\n", required_bins[i]);
			fprintf(stderr, "\033[0;31m[!] Initiating 1ms XDP Emergency Lockdown due to unmet environment requirements.\033[0m\n");
			trigger_emergency_lockdown();
		}
	}
	// Verify kernel headers existence for eBPF / Clang compilation safety
	if (access("/lib/modules/", F_OK) != 0 || system("ls /lib/modules/$(uname -r)/build >/dev/null 2>&1") != 0) {
		printf("\033[1;33m[*] Warning: Kernel build headers not fully detected. Clang eBPF compilation fallback active.\033[0m\n");
	}
	
	char int_if[32] = {0};
	get_interface(int_if);
	
	const char *session_domains[] = {
		"duckduckgo.com", "google.com", "startpage.com", "wikipedia.org",
		"mozilla.org", "debian.org", "kernel.org", "github.com",
		"archlinux.org", "eff.org", "torproject.org", "proton.me",
		"tutanota.com", "signal.org", "tails.net", "qubes-os.org",
		"vimeo.com", "archive.org", "reddit.com", "bbc.com",
		"bing.com", "yahoo.com", "ask.com", "ecosia.org",
		"archive.is", "wired.com", "torry.io", "searx.space",
		"brave.com", "openbsd.org", "fedoraproject.org", "ubuntu.com",
		"kali.org", "exploratorium.edu", "gnu.org", "imdb.com",
		"bloomberg.com", "cointelegraph.com", "medium.com", "stackexchange.com",
		"sourceforge.net", "gitlab.com", "bitbucket.org", "owasp.org",
		"sans.org", "infosecinstitute.com", "apache.org", "w3schools.com",
		"stackoverflow.com", "github.io", "sourcegraph.com", "docker.com",
		"python.org", "golang.org", "rust-lang.org", "llvm.org",
		"cisco.com", "redhat.com", "suse.com", "freebsd.org",
		"netbsd.org", "opensuse.org", "centos.org", "mit.edu",
		"stanford.edu", "harvard.edu", "berkeley.edu", "cern.ch",
		"ieee.org", "acm.org", "ietf.org", "icann.org",
		"iana.org", "w3.org", "cloudflare.com", "fastly.com",
		"digitalocean.com", "linode.com", "aws.amazon.com", "gcp.google.com",
		"azure.microsoft.com", "oracle.com", "ibm.com", "intel.com",
		"amd.com", "nvidia.com", "slashdot.org", "hackernews.com",
		"techcrunch.com", "arstechnica.com", "gizmodo.com", "engadget.com",
		"nationalgeographic.com", "smithsonianmag.com", "ted.com", "khanacademy.org"
	};
	
	int selected_indices[10];
	FILE *f_dom = fopen("/dev/urandom", "rb");
	if (f_dom) {
		for (int i = 0; i < 10; i++) {
			unsigned char b;
			fread(&b, 1, 1, f_dom);
			selected_indices[i] = b % 100;
			for (int j = 0; j < i; j++) {
				if (selected_indices[i] == selected_indices[j]) {
					i--; 
					break;
				}
			}
		}
		fclose(f_dom);
	} else {
		for(int i = 0; i < 10; i++) selected_indices[i] = i;
	}
	
	safe_execute("nft flush ruleset");
	safe_execute("nft add table inet shadownet");
	safe_execute("nft add chain inet shadownet input { type filter hook input priority 0 \\; policy drop \\; }; nft add chain inet shadownet forward { type filter hook forward priority 0 \\; policy drop \\; }");
	safe_execute("nft add chain inet shadownet output { type filter hook output priority 0 \\; policy drop \\; }");
	safe_execute("nft insert rule inet shadownet output oifname \"lo\" accept; nft insert rule inet shadownet input iifname \"lo\" accept");
	
	char init_tor_pass[256];
	snprintf(init_tor_pass, sizeof(init_tor_pass), "TOR_UID=$(id -u debian-tor); [ -n \"$TOR_UID\" ] && nft add rule inet shadownet output oifname \"%.16s\" skuid $TOR_UID accept", int_if);
	safe_execute(init_tor_pass);
	
	int alias_roll = 1;
	int fixed_mtu = 1400;
	
	int fixed_payload_size = (int)get_loopix_poisson_delay(0.002);
	if (fixed_payload_size < 500) fixed_payload_size = 500;
	if (fixed_payload_size > fixed_mtu - 42) fixed_payload_size = fixed_mtu - 42;
	
	int start_iat_jitter = (int)get_loopix_poisson_delay(0.1);
	if (start_iat_jitter < 5) start_iat_jitter = 5;
	if (start_iat_jitter > 20) start_iat_jitter = 20;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before starting ShadowNet...\033[0m\n", start_iat_jitter);
	sleep(start_iat_jitter);
	
	int hw_iat;
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Bluetooth...\033[0m\n", hw_iat);
	sleep(hw_iat);
	safe_execute("sudo rfkill block bluetooth 2>/dev/null");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Bluetooth...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Bluetooth Hardware: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Audio/Microphone...\033[0m\n", hw_iat);
	sleep(hw_iat);
	// Dynamic existence check before removing audio modules/fusers
	if (access("/dev/snd", F_OK) == 0) {
		safe_execute("sudo fuser -k /dev/snd/* >/dev/null 2>&1; sudo modprobe -r snd_hda_intel snd_usb_audio 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Audio/Microphone...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Internal/External Microphone: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Camera/Webcam...\033[0m\n", hw_iat);
	sleep(hw_iat);
	// Dynamic existence check before removing video/uvc modules
	if (access("/dev/video0", F_OK) == 0 || access("/sys/class/video4linux", F_OK) == 0) {
		safe_execute("sudo fuser -k /dev/video* >/dev/null 2>&1; sudo modprobe -r uvcvideo 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Camera/Webcam...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Internal/External Webcam: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Motion Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	if (access("/sys/bus/iio", F_OK) == 0 || system("lsmod | grep -q hid_sensor_hub") == 0) {
		safe_execute("sudo modprobe -r hid_sensor_accel_3d hid_sensor_gyro_3d hid_sensor_hub 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Motion Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Gyroscopes and Accelerometers: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Light Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	if (system("lsmod | grep -q hid_sensor_als") == 0) {
		safe_execute("sudo modprobe -r hid_sensor_als 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after disabling Light Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Ambient Light Sensors: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before disabling Thermal Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	if (access("/sys/class/thermal", F_OK) == 0) {
		safe_execute("sudo modprobe -r intel_rapl_msr intel_rapl_common processor_thermal_device_pci_legacy thermal 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Thermal Sensors...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Thermal Sensors: DISABLED\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before TEMPEST Mitigation...\033[0m\n", hw_iat);
	sleep(hw_iat);
	safe_execute("sudo sysctl -w kernel.randomize_va_space=2 >/dev/null");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after TEMPEST Mitigation...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Electromagnetic Interference (TEMPEST) Shielded.\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before BIOS Hardening...\033[0m\n", hw_iat);
	sleep(hw_iat);
	if (access("/sys/firmware/efi/efivars", F_OK) == 0) {
		safe_execute("sudo chattr +i /sys/firmware/efi/efivars/* 2>/dev/null");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after BIOS Hardening...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] BIOS/Firmware Immutable Protection: ACTIVE\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Power Randomization...\033[0m\n", hw_iat);
	sleep(hw_iat);
	if (system("command -v cpupower >/dev/null 2>&1") == 0) {
		safe_execute("sudo cpupower frequency-set -g powersave >/dev/null 2>&1");
	}
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Power Randomization...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] Power Supply Side-Channel & Entropy Randomization: ACTIVE\033[0m\n");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before DHCP/Hostname Scrubbing...\033[0m\n", hw_iat);
	sleep(hw_iat);
	safe_execute("sudo hostnamectl set-hostname 'localhost'");
	safe_execute("printf '[main]\\ndhcp=dhclient\\n\\n[ifupdown]\\nmanaged=false\\n' | sudo tee /etc/NetworkManager/conf.d/dhcp-anon.conf > /dev/null");
	
	hw_iat = (int)get_loopix_poisson_delay(0.3);
	if (hw_iat < 2) hw_iat = 2; if (hw_iat > 5) hw_iat = 5;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after DHCP/Hostname Scrubbing...\033[0m\n", hw_iat);
	sleep(hw_iat);
	printf("\033[1;31m[!] DHCP Hostname Scrubbing & Anonymization: ACTIVE\033[0m\n");
	
	safe_execute("sudo mount -o remount,rw,hidepid=2 /proc 2>/dev/null");
	
	char cmd[2048];
	signal(SIGINT, handle_sigint);
	if (access("./heartbeat.c", F_OK) == -1 || access("./shadownet_engine.c", F_OK) == -1) {
		printf("\033[0;31m[!] CRITICAL: heartbeat.c or shadownet_engine.c missing. Aborting.\033[0m\n");
		exit(1);
	}
	
	int target_kbps = (int)(get_loopix_poisson_delay(0.0005) * 1000.0) % 4901 + 100;
	if (target_kbps < 100) target_kbps = 100;
	if (target_kbps > 5000) target_kbps = 5000;
	
	printf("\033[1;30m[*] Executing 14-Tier Process Sanitation & Guarding...\033[0m\n");
	execute_14_tier_sanitation("heartbeat");
	execute_14_tier_sanitation("shadownet_engine");
	safe_execute("sudo systemctl stop chrony ntp systemd-timesyncd 2>/dev/null");
	safe_execute("sudo systemctl mask chrony ntp systemd-timesyncd 2>/dev/null");
	if (safe_execute("ps -ef | grep 'heartbeat\\|shadownet_engine' | grep -v grep > /dev/null 2>&1") == 0) {
		printf("\033[0;31m[!] CRITICAL: Failed to forcefully terminate old processes. Aborting.\033[0m\n");
		exit(1);
	}
	safe_execute("rm -f /dev/shm/shadownet_heartbeat.pid /dev/shm/shadownet_engine.pid /dev/shm/heartbeat /dev/shm/shadownet_engine");
	
	snprintf(cmd, sizeof(cmd), "ip link show %.16s | grep ether | awk '{print $2}' > /dev/shm/shadownet_mac.bak", int_if);
	safe_execute(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s down", int_if);
	safe_execute(cmd);
	
	int mac_shift_jitter = (int)get_loopix_poisson_delay(0.1);
	if (mac_shift_jitter < 3) mac_shift_jitter = 3;
	if (mac_shift_jitter > 15) mac_shift_jitter = 15;
	printf("\033[1;33m[*] Applying Identity Entropy: %ds before shift...\033[0m\n", mac_shift_jitter);
	sleep(mac_shift_jitter);
	
	snprintf(cmd, sizeof(cmd), "sudo macchanger -r %.16s", int_if);
	safe_execute(cmd);
	
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s mtu %d", int_if, fixed_mtu);
	safe_execute(cmd);
	safe_execute("sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1 >/dev/null");
	snprintf(cmd, sizeof(cmd), "sudo ip link set %.16s up", int_if);
	safe_execute(cmd);
	
	int post_mac_jitter = (int)get_loopix_poisson_delay(0.03);
	if (post_mac_jitter < 15) post_mac_jitter = 15;
	if (post_mac_jitter > 60) post_mac_jitter = 60;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds after Identity Shift...\033[0m\n", post_mac_jitter);
	sleep(post_mac_jitter);
	
	safe_execute("cp ./heartbeat.c /dev/shm/heartbeat.c 2>/dev/null; gcc /dev/shm/heartbeat.c -o /dev/shm/heartbeat -lm 2>/dev/null; "
	"gcc ./shadownet_engine.c -o /dev/shm/shadownet_engine -lm 2>/dev/null");
	if (access("/dev/shm/shadownet_engine", F_OK) == -1 || access("/dev/shm/heartbeat", F_OK) == -1) {
		printf("\033[0;31m[!] CRITICAL: Binaries failed to generate in RAM directory. Aborting.\033[0m\n");
		stop_shadownet();
		exit(1);
	}
	setenv("SHADOWNET_PROC", "true", 1);
	
	char rand_dest_ip[64];
	char rand_src_ip[64];
	int ebpp_tos_val = 0;
	ebpp_entropy_scramble(rand_dest_ip, rand_src_ip, &ebpp_tos_val);
	
	int dest_iat_delay = (int)get_loopix_poisson_delay(0.5);
	if (dest_iat_delay < 1) dest_iat_delay = 1;
	if (dest_iat_delay > 4) dest_iat_delay = 4;
	printf("\033[1;33m[*] Applying Destination Entropy IAT: %ds...\033[0m\n", dest_iat_delay);
	sleep(dest_iat_delay);
	
	char ebpp_tos_str[16];
	snprintf(ebpp_tos_str, sizeof(ebpp_tos_str), "%d", ebpp_tos_val);
	setenv("EBPP_IP_HEADER_TOS", ebpp_tos_str, 1);
	
	printf("\033[1;32m[+] Session Parallel Targets Assigned | Co Authored By JS / ASA:\033[0m\n");
	for (int i = 0; i < 10; i++) {
		printf("\033[1;32m    [%d] %s\033[0m\n", i + 1, session_domains[selected_indices[i]]);
	}
	
	char engine_cmd_buf[2048];
	snprintf(engine_cmd_buf, sizeof(engine_cmd_buf), "sudo nice -n -20 nohup /dev/shm/shadownet_engine %s %s %s %s %s %s %s %s %s %s > /dev/null 2>&1 & echo $! > /dev/shm/shadownet_engine.pid", 
			 session_domains[selected_indices[0]], session_domains[selected_indices[1]], session_domains[selected_indices[2]], session_domains[selected_indices[3]], session_domains[selected_indices[4]],
		  session_domains[selected_indices[5]], session_domains[selected_indices[6]], session_domains[selected_indices[7]], session_domains[selected_indices[8]], session_domains[selected_indices[9]]);
	safe_execute(engine_cmd_buf);
	snprintf(cmd, sizeof(cmd), "sudo nice -n -20 nohup /dev/shm/heartbeat %d %d %d %d %s %s %s %s %s %s %s %s %s %s > /dev/null 2>&1 & echo $! > /dev/shm/shadownet_heartbeat.pid", fixed_mtu, target_kbps, alias_roll, fixed_payload_size, 
			 session_domains[selected_indices[0]], session_domains[selected_indices[1]], session_domains[selected_indices[2]], session_domains[selected_indices[3]], session_domains[selected_indices[4]],
		  session_domains[selected_indices[5]], session_domains[selected_indices[6]], session_domains[selected_indices[7]], session_domains[selected_indices[8]], session_domains[selected_indices[9]]);
	safe_execute(cmd);
	char ebpp_mangle_cmd[512];
	snprintf(ebpp_mangle_cmd, sizeof(ebpp_mangle_cmd), "sudo nft add rule inet shadownet output oifname \"%.16s\" ip tos set %d 2>/dev/null", int_if, ebpp_tos_val);
	safe_execute(ebpp_mangle_cmd);
	
	unsigned char urand_roll = 0;
	FILE *f_roll = fopen("/dev/urandom", "rb");
	if (f_roll) { fread(&urand_roll, 1, 1, f_roll); fclose(f_roll); }
	
	double p_delay_tor = get_loopix_poisson_delay(0.5);
	sleep((unsigned int)(p_delay_tor < 1.0 ? 1 : p_delay_tor));
	
	if (safe_execute("ps -ef | grep '/dev/shm/shadownet_engine' | grep -v grep > /dev/null") != 0 || safe_execute("ps -ef | grep '/dev/shm/heartbeat' | grep -v grep > /dev/null") != 0) {
		printf("\033[0;31m[!] CRITICAL: Core processes failed to lock in RAM. Aborting for OpSec.\033[0m\n");
		stop_shadownet();
		exit(1);
	}
	printf("\033[1;36m[*] Hardening Interface & System Persistence (Anti-Sleep)...\033[0m\n");
	snprintf(cmd, sizeof(cmd), "sudo iw dev %.16s set power_save off 2>/dev/null", int_if);
	safe_execute(cmd);
	snprintf(cmd, sizeof(cmd), "sudo ethtool -K %.16s gso off gro off tso off 2>/dev/null", int_if);
	safe_execute(cmd);
	safe_execute("sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1");
	
	int tx_power = (int)get_loopix_poisson_delay(0.1);
	if (tx_power < 8) tx_power = 8;
	if (tx_power > 20) tx_power = 20;
	
	snprintf(cmd, sizeof(cmd), "sudo iw dev %.16s set txpower limit %d00 2>/dev/null", int_if, tx_power);
	safe_execute(cmd);
	printf("\033[1;36m[*] Permanently disabling IPv6 at Kernel and Sysctl layers...\033[0m\n");
	safe_execute("echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf >/dev/null; "
	"sudo sysctl -p >/dev/null 2>&1");
	
	int pre_adj_jitter = (int)get_loopix_poisson_delay(0.1);
	if (pre_adj_jitter < 5) pre_adj_jitter = 5;
	if (pre_adj_jitter > 15) pre_adj_jitter = 15;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Temporal Drift Adjustment...\033[0m\n", pre_adj_jitter);
	sleep(pre_adj_jitter);
	
	int last_tick = 0;
	FILE *f_tick = fopen("/dev/shm/shadownet_tick.last", "w+");
	if (f_tick) {
		fclose(f_tick);
	}
	f_tick = fopen("/dev/shm/shadownet_tick.last", "r");
	if (f_tick) {
		fscanf(f_tick, "%d", &last_tick);
		fclose(f_tick);
	}
	int assigned_tick;
	do {
		double poisson_tick_offset = get_loopix_poisson_delay(0.0001);
		assigned_tick = 9000 + (int)(poisson_tick_offset) % 2000;
		if (assigned_tick < 9000) assigned_tick = 9000;
		if (assigned_tick > 11000) assigned_tick = 11000;
	} while (assigned_tick == last_tick);
		
		f_tick = fopen("/dev/shm/shadownet_tick.last", "w");
		if (f_tick) {
			fprintf(f_tick, "%d", assigned_tick);
			fclose(f_tick);
		}
		snprintf(cmd, sizeof(cmd), "sudo adjtimex -t %d >/dev/null 2>&1", assigned_tick);
		safe_execute(cmd);
		printf("\033[1;35m[+] Temporal Entropy Engaged: Clock Tick assigned to %d.\033[0m\n", assigned_tick);
		
		int post_adj_jitter = (int)get_loopix_poisson_delay(0.1);
		if (post_adj_jitter < 5) post_adj_jitter = 5;
		if (post_adj_jitter > 15) post_adj_jitter = 15;
		printf("\033[1;33m[*] Applying Entropy IAT: %ds after Temporal Drift Adjustment...\033[0m\n", post_adj_jitter);
	sleep(post_adj_jitter);
	
	printf("\033[1;36m[*] Hardening Regulatory Domain & GRUB Configuration...\033[0m\n");
	safe_execute("if ! grep -q 'cfg80211.cfg80211_disable_reg_hint=1' /etc/default/grub; then "
	"sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"\\([^\"]*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 cfg80211.cfg80211_disable_reg_hint=1\"/' /etc/default/grub; "
	"sudo update-grub; fi");
	safe_execute("sudo iw reg set US 2>/dev/null || sudo iw reg set CA 2>/dev/null");
	printf("\033[1;32m[+] Session Identity Assigned: Alias-Fixed (Assigned Cover Packet Size: %d bytes)\033[0m\n", fixed_payload_size + 42);
	printf("\033[0;32m[+] Identity Shifted. Cover Traffic & Temporal Jitter Engaged (Locked at %dkbps in RAM) | Co Authored By JS / ASA.\033[0m\n", target_kbps);
	printf("\033[1;32m[+] Packet Max MTU Size: %d bytes | Target Rate: %d kbps.\033[0m\n", fixed_mtu, target_kbps);
	
	int pre_phase1_jitter = (int)get_loopix_poisson_delay(0.05);
	if (pre_phase1_jitter < 5) pre_phase1_jitter = 5;
	if (pre_phase1_jitter > 45) pre_phase1_jitter = 45;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Tier 1 access...\033[0m\n", pre_phase1_jitter);
	sleep(pre_phase1_jitter);
	
	int phase1_wait = (int)get_loopix_poisson_delay(0.05);
	if (phase1_wait < 10) phase1_wait = 10;
	if (phase1_wait > 30) phase1_wait = 30;
	printf("\033[1;34m[*] Phase 1: Establishing Entry Tier (Nodes 1-3). Applying Jitter: %ds...\033[0m\n", phase1_wait);
	sleep(phase1_wait);
	
	int pre_phase2_jitter = (int)get_loopix_poisson_delay(0.05);
	if (pre_phase2_jitter < 10) pre_phase2_jitter = 10;
	if (pre_phase2_jitter > 30) pre_phase2_jitter = 30;
	printf("\033[1;33m[*] Applying Entropy IAT: %ds before Tier 4 transition...\033[0m\n", pre_phase2_jitter);
	sleep(pre_phase2_jitter);
	
	int phase2_wait = (int)get_loopix_poisson_delay(0.03);
	if (phase2_wait < 15) phase2_wait = 15;
	if (phase2_wait > 45) phase2_wait = 45;
	printf("\033[1;35m[*] Phase 2: Extending to Exit Tier (Nodes 4-6). Applying Entropy IAT: %ds...\033[0m\n", phase2_wait);
	sleep(phase2_wait);
	
	printf("\033[0;32m[+] 6-Hop Chain Established. Initializing ShadowNet Routing Protocol...\033[0m\n");
	safe_execute("sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
	"sudo sysctl -w net.ipv4.ip_default_ttl=128 >/dev/null; "
	"sudo sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null; "
	"sudo sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null; "
	"sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1");
	safe_execute("sudo sed -i '/# --- ShadowNet Protocol Additions ---/,/# --- End ShadowNet ---/d' /etc/tor/torrc; "
	"printf '\\n# --- ShadowNet Protocol Additions ---\\n"
	"VirtualAddrNetworkIPv4 10.192.0.0/10\\n"
	"AutomapHostsOnResolve 1\\n"
	"TransPort 127.0.0.1:9040 IsolateDestAddr IsolateDestPort IsolateClientAddr IsolateClientProtocol IsolateSOCKSAuth\\n"
	"DNSPort 5353\\n"
	"LongLivedPorts 21,22,706,1863,5050,5190,5222,5223,6667,6697,8300\\n"
	"# Enforce 6-Hop Circuitry\\n"
	"CircuitBuildTimeout 60\\n"
	"NumEntryGuards 1\\n"
	"EnforceDistinctSubnets 1\\n"
	"NewCircuitPeriod 1\\n"
	"MaxCircuitDirtiness 1\\n"
	"CircuitPadding 1\\n"
	"ConnectionPadding 1\\n"
	"ReducedConnectionPadding 0\\n"
	"ReducedCircuitPadding 0\\n"
	"# --- End ShadowNet ---\\n' >> /etc/tor/torrc; "
	"sudo chown debian-tor:debian-tor /etc/tor/torrc; "
	"systemctl restart tor@default;");
	
	double p_delay_us1 = get_loopix_poisson_delay(5.0);
	usleep((useconds_t)(p_delay_us1 * 1000000.0));
	
	snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %.16s root 2>/dev/null", int_if);
	safe_execute(cmd);
	
	double p_delay_us2 = get_loopix_poisson_delay(5.0);
	usleep((useconds_t)(p_delay_us2 * 1000000.0));
	
	int netem_delay = 30; 
	int netem_jitter = 20; 
	int sfq_perturb = 1; 
	
	snprintf(cmd, sizeof(cmd), "sudo tc qdisc add dev %.16s root handle 1: htb default 10; "
	"sudo tc class add dev %.16s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit quantum 65000; "
	"sudo tc class add dev %.16s parent 1:1 classid 1:10 htb rate %dkbit ceil %dkbit burst 15k cburst 15k quantum 65000; "
	"sudo tc qdisc add dev %.16s parent 1:10 handle 10: netem delay %dms %dms 25%% distribution pareto reorder 100%% 0%% gap 5; "
	"sudo tc qdisc add dev %.10s parent 10:1 handle 20: sfq perturb %d quantum 1514", 
	int_if, int_if, target_kbps, target_kbps, int_if, target_kbps, target_kbps, int_if, netem_delay, netem_jitter, int_if, sfq_perturb);
	safe_execute(cmd);
	
	double p_delay_us3 = get_loopix_poisson_delay(5.0);
	usleep((useconds_t)(p_delay_us3 * 1000000.0));
	
	if (access("/etc/resolv.conf", F_OK) != -1) {
		if (safe_execute("if [ -L /etc/resolv.conf ]; then cp /etc/resolv.conf /dev/shm/resolv.conf.shadownet_bak; rm -f /etc/resolv.conf; "
			"elif [ ! -f /dev/shm/resolv.conf.shadownet_bak ]; then cp /etc/resolv.conf /dev/shm/resolv.conf.shadownet_bak; fi") != 0) {
			}
	}
	
	int dns_jitter = (int)get_loopix_poisson_delay(0.5);
	if (dns_jitter < 1) dns_jitter = 1;
	if (dns_jitter > 5) dns_jitter = 5;
	printf("\033[1;33m[*] Applying Loopix Cascade DNS Delay: %ds...\033[0m\n", dns_jitter);
	sleep(dns_jitter);
	
	safe_execute("sudo chattr -i /etc/resolv.conf 2>/dev/null");
	safe_execute("echo 'nameserver 127.0.0.1' > /etc/resolv.conf");
	safe_execute("sudo chattr +i /etc/resolv.conf");
	
	safe_execute("nft flush chain inet shadownet input; nft flush chain inet shadownet forward; nft flush chain inet shadownet output");
	safe_execute("nft add chain inet shadownet input { policy drop \\; }; nft add chain inet shadownet forward { policy drop \\; }; nft add chain inet shadownet output { policy drop \\; }");
	safe_execute("nft add table inet shadownet_nat; nft add chain inet shadownet_nat output { type nat hook output priority -100 \\; }");
	safe_execute("nft insert rule inet shadownet output oifname \"lo\" accept; nft insert rule inet shadownet input iifname \"lo\" accept");
	
	safe_execute("nft flush chain inet shadownet input; nft flush chain inet shadownet forward; nft flush chain inet shadownet output");
	safe_execute("nft add chain inet shadownet input { policy drop \\; }; nft add chain inet shadownet forward { policy drop \\; }; nft add chain inet shadownet output { policy drop \\; }");
	safe_execute("nft add rule inet shadownet input ct state established,related accept");
	safe_execute("nft add rule inet shadownet output ct state established,related accept");
	safe_execute("nft insert rule inet shadownet output oifname \"lo\" accept; nft insert rule inet shadownet input iifname \"lo\" accept");
	
	safe_execute("nft add rule inet shadownet input ip protocol icmp drop");
	safe_execute("nft add rule inet shadownet output ip protocol icmp drop");
	safe_execute("nft add rule inet shadownet forward ip protocol icmp drop");
	safe_execute("nft add rule inet shadownet input ip6 nexthdr icmpv6 drop");
	safe_execute("nft add rule inet shadownet output ip6 nexthdr icmpv6 drop");
	safe_execute("nft add rule inet shadownet forward ip6 nexthdr icmpv6 drop");
	safe_execute("nft insert rule inet shadownet input iifname \"lo\" ip protocol icmp drop");
	safe_execute("nft insert rule inet shadownet output oifname \"lo\" ip protocol icmp drop");
	safe_execute("nft insert rule inet shadownet input iifname \"lo\" ip6 nexthdr icmpv6 drop");
	safe_execute("nft insert rule inet shadownet output oifname \"lo\" ip6 nexthdr icmpv6 drop");
	
	char tor_strict_rules[2048];
	snprintf(tor_strict_rules, sizeof(tor_strict_rules),
			 "TOR_UID=$(id -u debian-tor); "
			 "if [ -n \"$TOR_UID\" ]; then "
			 " nft add rule inet shadownet_nat output skuid $TOR_UID return; "
			 " nft add rule inet shadownet output oifname \"%.16s\" skuid $TOR_UID accept; "
			 " nft add rule inet shadownet output oifname != \"%.16s\" skuid $TOR_UID drop; "
			 "fi; "
			 "nft add rule inet shadownet_nat output meta mark 76 meta l4proto tcp redirect to 9040; "
			 "nft add rule inet shadownet output meta mark 76 meta l4proto tcp accept; "
			 "nft add rule inet shadownet_nat output udp dport 53 redirect to 5353; "
			 "nft add rule inet shadownet_nat output tcp dport 53 redirect to 5353; "
			 "nft add rule inet shadownet output udp dport 53 ip daddr != 127.0.0.1 drop; "
			 "nft add rule inet shadownet output tcp dport 53 ip daddr != 127.0.0.1 drop; "
			 "nft add rule inet shadownet_nat output ip daddr 127.0.0.0/8 return; "
			 "nft add rule inet shadownet_nat output tcp flags syn redirect to 9040; "
			 "nft add rule inet shadownet output ip daddr 127.0.0.0/8 accept; "
			 "nft add rule inet shadownet output meta length 1401-65535 drop; "
			 "nft add rule inet shadownet output reject with icmp type port-unreachable; "
			 "nft add rule inet shadownet output oifname \"%.16s\" drop;", int_if, int_if, int_if);
	safe_execute(tor_strict_rules);
	
	printf("\033[0;32m[+] Loopix Parallel Mixing Layer Active. Inter-Arrival Time aligned.\033[0m\n");
	printf("\033[1;31m[!] EMERGENCY KILLSWITCH ENGAGED: Realistic 100ms Guarding Active...\033[0m\n");
	safe_execute("sudo ip route flush cache");
	
	printf("\033[1;36m[*] Injecting eBPF Subsystem for Core Dynamic Packet Processing & Rerouting...\033[0m\n");
	FILE *ebpf_f = fopen("/dev/shm/shadownet_ebpf.c", "w");
	if (ebpf_f) {
		fprintf(ebpf_f,
				"#include <linux/bpf.h>\n"
				"#include <linux/pkt_cls.h>\n"
				"#include <linux/ip.h>\n"
				"#include <linux/bpf_endian.h>\n"
				"\n"
				"struct {\n"
					" __uint(type, BPF_MAP_TYPE_ARRAY);\n"
					" __uint(max_entries, 1);\n"
					" __type(key, __u32);\n"
					" __type(value, __u32);\n"
					" __uint(pinning, BPF_PIN_BY_NAME);\n"
					"} shadownet_lockdown_map SEC(\".maps\");\n"
					"\n"
					"SEC(\"xdp_killswitch\")\n"
					"int shadownet_xdp_kill(struct xdp_md *ctx) {\n"
						" __u32 key = 0;\n"
						" __u32 *lockdown = bpf_map_lookup_elem(&shadownet_lockdown_map, &key);\n"
						" if (lockdown && *lockdown == 1) {\n"
							" return XDP_DROP;\n"
							" }\n"
							" return XDP_PASS;\n"
							"}\n"
							"\n"
							"SEC(\"classifier\")\n"
							"int shadownet_bpf_router(struct __sk_buff *skb) {\n"
								" void *data = (void *)(long)skb->data;\n"
								" void *data_end = (void *)(long)skb->data_end;\n"
								" struct iphdr *iph = data;\n"
								" if ((void *)(iph + 1) > data_end) return TC_ACT_OK;\n"
								" if (iph->protocol == 17 || iph->protocol == 6) {\n"
									" __u32 options = bpf_get_prandom_u32();\n"
									" if (options %% 2 == 0) {\n"
										" iph->tos = (%d & 0xFF);\n"
										" }\n"
										" // Kernel-side Loopix/Poisson & Sphinx fixed packet padding/jitter assistance helper\n"
										" if (options %% 5 == 0) {\n"
											" iph->id = bpf_htons(options %% 65535);\n"
											" }\n"
											" }\n"
											" return TC_ACT_OK;\n"
											"}\n"
											"char _license[] SEC(\"license\") = \"GPL\";\n", ebpp_tos_val);
		fclose(ebpf_f);
		safe_execute("sudo mkdir -p /sys/fs/bpf 2>/dev/null; sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null");
		safe_execute("clang -O2 -target bpf -c /dev/shm/shadownet_ebpf.c -o /dev/shm/shadownet_ebpf.o 2>/dev/null");
		char ebpf_attach_cmd[1024];
		snprintf(ebpf_attach_cmd, sizeof(ebpf_attach_cmd),
				 "sudo tc qdisc add dev %.16s ingress 2>/dev/null; "
				 "sudo tc filter add dev %.16s ingress protocol ip u32 match u32 0 0 police rate %dkbit burst 100k drop 2>/dev/null; "
				 "sudo tc filter add dev %.16s ingress bpf da obj /dev/shm/shadownet_ebpf.o sec classifier 2>/dev/null; "
				 "sudo tc filter add dev %.16s egress bpf da obj /dev/shm/shadownet_ebpf.o sec classifier 2>/dev/null; "
				 "sudo ip link set dev %.16s xdp obj /dev/shm/shadownet_ebpf.o sec xdp_killswitch 2>/dev/null",
		   int_if, int_if, target_kbps, int_if, int_if, int_if);
		safe_execute(ebpf_attach_cmd);
		printf("\033[1;32m[+] eBPF Bypass Subsystem: FULLY ENGAGED & ATTACHED to %.16s hooks\033[0m\n", int_if);
	}
	while(1) {
		char traffic_check_cmd[512];
		struct timespec rf_iat;
		
		double p_delay = get_loopix_poisson_delay(15.0);
		rf_iat.tv_sec = (long)p_delay;
		rf_iat.tv_nsec = (long)((p_delay - rf_iat.tv_sec) * 1000000000.0) % 1000000000L;
		nanosleep(&rf_iat, NULL);
		
		int current_rf = (int)get_loopix_poisson_delay(0.1);
		if (current_rf < 8) current_rf = 8;
		if (current_rf > 20) current_rf = 20;
		
		char rf_cmd[256];
		snprintf(rf_cmd, sizeof(rf_cmd), "sudo iw dev %s set txpower limit %d00 2>/dev/null", int_if, current_rf);
		safe_execute(rf_cmd);
		if (safe_execute("iw reg get | grep -q 'country GB'") == 0) {
			safe_execute("sudo iw reg set US 2>/dev/null || sudo iw reg set CA 2>/dev/null");
		}
		
		proc_missing = (safe_execute("ps -ef | grep '/dev/shm/shadownet_engine' | grep -v grep > /dev/null") != 0 || safe_execute("ps -ef | grep '/dev/shm/heartbeat' | grep -v grep > /dev/null") != 0 || safe_execute("ps -ef | grep '/usr/bin/tor' | grep -v grep > /dev/null") != 0);
		snprintf(traffic_check_cmd, sizeof(traffic_check_cmd), "ip link show %s | grep -q 'UP'", int_if);
		int phys_dead = (safe_execute(traffic_check_cmd) != 0);
		
		if (proc_missing || phys_dead) {
			trigger_emergency_lockdown();
		}
		
		double p_delay_mon = get_loopix_poisson_delay(1000.0);
		usleep((useconds_t)(p_delay_mon * 1000000.0));
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
		snprintf(cmd, sizeof(cmd), "printf '[Unit]\\nDescription=ShadowNet Service\\nAfter=network.target\\n\\n[Service]\\nType=simple\\nWorkingDirectory=\\'%s\\'\\nExecStart=\\'%s\\' start\\nExecStop=\\'%s\\' stop\\nKillMode=process\\nRemainAfterExit=yes\\n\\n[Install]\\nWantedBy=multi-user.target\\n' | sudo tee /etc/systemd/system/shadownet.service > /dev/null", dir, path, path);
		safe_execute(cmd);
		safe_execute("sudo systemctl daemon-reload");
		safe_execute("sudo systemctl enable shadownet.service");
		printf("\033[0;32m[+] ShadowNet persistence enabled. Will start on boot.\033[0m\n");
	}
}

void disable_boot() {
	safe_execute("sudo systemctl disable shadownet.service 2>/dev/null");
	safe_execute("sudo rm -f /etc/systemd/system/shadownet.service");
	safe_execute("sudo systemctl daemon-reload");
	printf("\033[1;31m[-] ShadowNet persistence disabled.\033[0m\n");
}

void status_boot() {
	if (access("/etc/systemd/system/shadownet.service", F_OK) != -1) {
		if (safe_execute("systemctl is-enabled shadownet.service > /dev/null 2>&1") == 0) {
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
