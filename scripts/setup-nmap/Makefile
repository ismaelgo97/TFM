.PHONY: all install verify

all: install verify

install:
	@echo "[*] Installing nmap..."
	sudo apt-get update -qq
	sudo apt-get install -y nmap
	@echo "[+] Done."

verify:
	@nmap --version | head -1
