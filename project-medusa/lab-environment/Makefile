# MEDUSA Healthcare Lab - Makefile
# Convenience commands for managing the Docker lab environment

.PHONY: help build up down restart logs status clean reset test backup

# Default target
.DEFAULT_GOAL := help

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
RESET  := \033[0m

help: ## Show this help message
	@echo "$(GREEN)MEDUSA Healthcare Lab - Available Commands$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

build: ## Build all Docker images
	@echo "$(GREEN)Building Docker images...$(RESET)"
	docker-compose build
	@echo "$(GREEN)Build complete!$(RESET)"

up: ## Start all services (detached mode)
	@echo "$(GREEN)Starting MEDUSA lab environment...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)Lab is starting. Use 'make logs' to monitor startup.$(RESET)"
	@echo ""
	@echo "$(YELLOW)Access Points:$(RESET)"
	@echo "  • EHR Web Portal: http://localhost:8080"
	@echo "  • EHR API:        http://localhost:3000"
	@echo "  • Log Viewer:     http://localhost:8081"
	@echo "  • SSH:            ssh admin@localhost -p 2222"
	@echo ""

down: ## Stop all services
	@echo "$(YELLOW)Stopping MEDUSA lab environment...$(RESET)"
	docker-compose down
	@echo "$(GREEN)Lab stopped.$(RESET)"

restart: ## Restart all services
	@echo "$(YELLOW)Restarting MEDUSA lab environment...$(RESET)"
	docker-compose restart
	@echo "$(GREEN)Lab restarted.$(RESET)"

logs: ## View logs from all services
	docker-compose logs -f

status: ## Show status of all containers
	@echo "$(GREEN)Container Status:$(RESET)"
	@docker-compose ps
	@echo ""
	@echo "$(GREEN)Resource Usage:$(RESET)"
	@docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

clean: down ## Stop services and remove containers
	@echo "$(YELLOW)Cleaning up containers and networks...$(RESET)"
	docker-compose down --remove-orphans
	@echo "$(GREEN)Cleanup complete.$(RESET)"

reset: ## Complete reset (removes volumes and data)
	@echo "$(RED)WARNING: This will delete ALL data including database contents!$(RESET)"
	@echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
	@sleep 5
	@echo "$(YELLOW)Performing complete reset...$(RESET)"
	docker-compose down -v --remove-orphans
	docker-compose build --no-cache
	docker-compose up -d
	@echo "$(GREEN)Reset complete! Environment rebuilt from scratch.$(RESET)"

quick-reset: ## Quick reset (keeps images, rebuilds containers)
	@echo "$(YELLOW)Quick reset...$(RESET)"
	docker-compose down -v
	docker-compose up -d
	@echo "$(GREEN)Quick reset complete!$(RESET)"

test: ## Run basic connectivity tests
	@echo "$(GREEN)Running connectivity tests...$(RESET)"
	@echo ""
	@echo "Testing EHR Web Portal..."
	@curl -s -o /dev/null -w "  HTTP %{http_code} - %{url_effective}\n" http://localhost:8080 || echo "  $(RED)FAILED$(RESET)"
	@echo "Testing EHR API..."
	@curl -s -o /dev/null -w "  HTTP %{http_code} - %{url_effective}\n" http://localhost:3000/health || echo "  $(RED)FAILED$(RESET)"
	@echo "Testing Log Viewer..."
	@curl -s -o /dev/null -w "  HTTP %{http_code} - %{url_effective}\n" http://localhost:8081 || echo "  $(RED)FAILED$(RESET)"
	@echo "Testing MySQL..."
	@docker-compose exec -T ehr-database mysqladmin ping -h localhost -u root -padmin123 > /dev/null 2>&1 && echo "  $(GREEN)MySQL is alive$(RESET)" || echo "  $(RED)MySQL FAILED$(RESET)"
	@echo ""
	@echo "$(GREEN)Tests complete!$(RESET)"

backup: ## Backup database to file
	@echo "$(GREEN)Backing up database...$(RESET)"
	@mkdir -p backups
	docker-compose exec -T ehr-database mysqldump -u root -padmin123 healthcare_db > backups/healthcare_db_$$(date +%Y%m%d_%H%M%S).sql
	@echo "$(GREEN)Backup saved to backups/ directory$(RESET)"

restore: ## Restore database from latest backup (use BACKUP_FILE=path to specify)
	@if [ -z "$(BACKUP_FILE)" ]; then \
		LATEST=$$(ls -t backups/*.sql 2>/dev/null | head -1); \
		if [ -z "$$LATEST" ]; then \
			echo "$(RED)No backup files found in backups/$(RESET)"; \
			exit 1; \
		fi; \
		echo "$(GREEN)Restoring from $$LATEST...$(RESET)"; \
		cat $$LATEST | docker-compose exec -T ehr-database mysql -u root -padmin123 healthcare_db; \
	else \
		echo "$(GREEN)Restoring from $(BACKUP_FILE)...$(RESET)"; \
		cat $(BACKUP_FILE) | docker-compose exec -T ehr-database mysql -u root -padmin123 healthcare_db; \
	fi
	@echo "$(GREEN)Restore complete!$(RESET)"

logs-web: ## View EHR web portal logs
	docker-compose logs -f ehr-webapp

logs-api: ## View API server logs
	docker-compose logs -f ehr-api

logs-db: ## View database logs
	docker-compose logs -f ehr-database

logs-ssh: ## View SSH server logs
	docker-compose logs -f ssh-server

shell-web: ## Open shell in web container
	docker-compose exec ehr-webapp /bin/bash

shell-api: ## Open shell in API container
	docker-compose exec ehr-api /bin/sh

shell-db: ## Open MySQL shell
	docker-compose exec ehr-database mysql -u root -padmin123 healthcare_db

shell-ssh: ## Open shell in SSH container
	docker-compose exec ssh-server /bin/bash

network-inspect: ## Inspect Docker networks
	@echo "$(GREEN)DMZ Network:$(RESET)"
	@docker network inspect medusa-dmz --format='{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
	@echo ""
	@echo "$(GREEN)Internal Network:$(RESET)"
	@docker network inspect medusa-internal --format='{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

volume-list: ## List all volumes
	@echo "$(GREEN)Docker Volumes:$(RESET)"
	@docker volume ls --filter name=medusa

prune: ## Remove unused Docker resources (careful!)
	@echo "$(YELLOW)Removing unused Docker resources...$(RESET)"
	docker system prune -f
	@echo "$(GREEN)Cleanup complete.$(RESET)"

update: ## Pull latest base images and rebuild
	@echo "$(GREEN)Pulling latest base images...$(RESET)"
	docker-compose pull
	docker-compose build --no-cache
	@echo "$(GREEN)Update complete!$(RESET)"

verify: ## Verify all services are healthy
	@echo "$(GREEN)Verifying service health...$(RESET)"
	@./scripts/verify.sh 2>/dev/null || echo "Run 'make up' first"

install-tools: ## Install helpful testing tools (local machine)
	@echo "$(GREEN)Installing helpful tools...$(RESET)"
	@echo "This will install: mysql-client, ftp, nmap, hydra"
	@echo "Press Ctrl+C to cancel, or wait 3 seconds..."
	@sleep 3
	@if [ "$$(uname)" = "Darwin" ]; then \
		brew install mysql-client nmap hydra; \
	elif [ "$$(uname)" = "Linux" ]; then \
		sudo apt-get update && sudo apt-get install -y mysql-client ftp nmap hydra; \
	else \
		echo "$(RED)Unsupported OS for automatic installation$(RESET)"; \
	fi

# Development shortcuts
dev: build up ## Build and start (development workflow)

watch: ## Watch logs with color
	docker-compose logs -f --tail=100

stats: ## Show resource statistics
	@docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Information
info: ## Show lab information
	@echo "$(GREEN)╔═══════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║     MEDUSA Healthcare Security Testing Lab           ║$(RESET)"
	@echo "$(GREEN)╚═══════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Services:$(RESET)"
	@echo "  • 8 vulnerable services"
	@echo "  • 2 isolated networks"
	@echo "  • 25+ documented vulnerabilities"
	@echo ""
	@echo "$(YELLOW)Documentation:$(RESET)"
	@echo "  • README.md - Overview"
	@echo "  • SETUP_GUIDE.md - Installation guide"
	@echo "  • NETWORK_ARCHITECTURE.md - Network design"
	@echo "  • VULNERABILITY_DOCUMENTATION.md - Exploit guide"
	@echo ""
	@echo "$(RED)⚠️  WARNING: FOR TESTING ONLY - DO NOT EXPOSE TO INTERNET$(RESET)"
	@echo ""

demo: ## Show demo credentials and URLs
	@echo "$(GREEN)═════════════════════════════════════════════════════$(RESET)"
	@echo "$(GREEN)         MEDUSA Lab - Quick Reference               $(RESET)"
	@echo "$(GREEN)═════════════════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(YELLOW)Web Interfaces:$(RESET)"
	@echo "  EHR Portal:  http://localhost:8080"
	@echo "  API Docs:    http://localhost:3000/api/info"
	@echo "  Logs:        http://localhost:8081"
	@echo ""
	@echo "$(YELLOW)Default Credentials:$(RESET)"
	@echo "  Web:    admin / admin123"
	@echo "  SSH:    admin / admin2024"
	@echo "  MySQL:  root / admin123"
	@echo "  FTP:    fileadmin / Files2024!"
	@echo "  LDAP:   cn=admin,dc=medcare,dc=local / admin123"
	@echo ""
	@echo "$(YELLOW)Example Commands:$(RESET)"
	@echo "  ssh admin@localhost -p 2222"
	@echo "  mysql -h localhost -P 3306 -u root -padmin123"
	@echo "  ftp localhost 21"
	@echo ""

