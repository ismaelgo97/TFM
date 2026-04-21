# ELK runs via Docker Compose (docker/docker-compose.yml)
# Start: cd docker && docker compose up -d
# Kibana: http://localhost:5601

ES_HOST = localhost
ES_PORT = 9200

.PHONY: status

status:
	@echo "--- Elasticsearch ---"
	@curl -s http://$(ES_HOST):$(ES_PORT) | python3 -m json.tool 2>/dev/null \
		|| echo "[-] Elasticsearch is not reachable. Is the stack running? (cd docker && docker compose up -d)"
	@echo ""
	@echo "--- Filebeat (container logs) ---"
	@docker logs filebeat --tail 20 2>/dev/null \
		|| echo "[-] Filebeat container not found."
