# Imports the TFM saved objects (data view + saved searches) into Kibana.
# The stack must already be running: cd docker && docker compose up -d

KIBANA_HOST = localhost
KIBANA_PORT = 5601
BUNDLE      = ../../docker/kibana/dashboards.ndjson

.PHONY: install status wait

install: wait
	@echo "[*] Importing saved objects from $(BUNDLE)..."
	@curl -s -X POST \
		"http://$(KIBANA_HOST):$(KIBANA_PORT)/api/saved_objects/_import?overwrite=true" \
		-H "kbn-xsrf: true" \
		--form file=@$(BUNDLE) \
		| python3 -m json.tool || echo "[-] Import failed"

wait:
	@echo "[*] Waiting for Kibana to become available..."
	@for i in $$(seq 1 30); do \
		if curl -s "http://$(KIBANA_HOST):$(KIBANA_PORT)/api/status" | grep -q '"level":"available"'; then \
			echo "[+] Kibana is up."; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "[-] Kibana never came up on port $(KIBANA_PORT)."; exit 1

status:
	@curl -s "http://$(KIBANA_HOST):$(KIBANA_PORT)/api/status" \
		| python3 -m json.tool 2>/dev/null \
		|| echo "[-] Kibana is not reachable."
