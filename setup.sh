#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
	echo -e "${RED}[!] Error: Run as root.${NC}"
	exit 1
	fi

	echo -e "${GREEN}[+] Installing Sovereign Dependencies & Lokinet...${NC}"
	apt-get update -y

	# Lokinet Repository Addition
	sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
	echo "deb https://deb.oxen.io bookworm main" | sudo tee /etc/apt/sources.list.d/oxen.list
	sudo apt update

	# Added badvpn (tun2socks) and torsocks
	DEBIAN_FRONTEND=noninteractive apt-get install -y \
	tor obfs4proxy iptables-persistent iproute2 curl \
	macchanger haveged net-tools bind9-dnsutils \
	adjtimex ethtool tshark build-essential lokinet \
	rfkill linux-cpupower torsocks i2pd libmnl-dev libnftnl-dev

	sudo chown -R root:root /var/lib/lokinet
	sudo chmod 644 /var/lib/lokinet/lokinet.ini
	sudo systemctl daemon-reload

	chmod +x shadownet.c
	chmod +x heartbeat.c
	chmod +x shadownet_engine.c

	echo -e "${GREEN}[V] Setup Complete.${NC}"
	echo -e "${GREEN}[*] Next Step: gcc shadownet.c -o shadownet${NC}"
	echo -e "${GREEN}[*] Then: sudo ./shadownet start${NC}"

