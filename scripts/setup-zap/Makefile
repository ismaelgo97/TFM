ZAP_HOST  = 127.0.0.1
ZAP_PORT  = 8080
ZAP_BIN   = /snap/bin/zaproxy

.PHONY: install run run-fg stop status

install:
	@echo "[*] Installing ZAP via snap..."
	sudo snap install zaproxy --classic
	@echo "[+] ZAP installed: $$($(ZAP_BIN) -version 2>/dev/null || echo 'installed at $(ZAP_BIN)')"

run:
	@echo "[*] Starting ZAP in daemon mode on $(ZAP_HOST):$(ZAP_PORT)..."
	$(ZAP_BIN) -daemon \
		-host $(ZAP_HOST) \
		-port $(ZAP_PORT) \
		-config api.disablekey=true \
		> /tmp/zap.log 2>&1 &
	@echo "[+] ZAP started. Logs: /tmp/zap.log"
	@echo "    Wait ~30s for ZAP to be fully ready before running web-scan."

run-fg:
	@echo "[*] Starting ZAP in foreground on $(ZAP_HOST):$(ZAP_PORT)..."
	$(ZAP_BIN) -daemon \
		-host $(ZAP_HOST) \
		-port $(ZAP_PORT) \
		-config api.disablekey=true

stop:
	@echo "[*] Stopping ZAP..."
	@pkill -f "zaproxy" && echo "[+] ZAP stopped." || echo "[-] ZAP was not running."

status:
	@if pgrep -f "zaproxy" > /dev/null; then \
		echo "[+] ZAP is running on $(ZAP_HOST):$(ZAP_PORT)"; \
	else \
		echo "[-] ZAP is not running."; \
	fi
