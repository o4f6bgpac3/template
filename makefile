.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## Start all services
	docker-compose up -d

.PHONY: down
down: ## Stop all services
	docker-compose down

.PHONY: logs
logs: ## Show logs for all services
	docker-compose logs -f

.PHONY: db-logs
db-logs: ## Show database logs
	docker-compose logs -f postgres

.PHONY: db-psql
db-psql: ## Connect to database with psql
	docker-compose exec postgres psql -U postgres -d template_dev

.PHONY: db-reset
db-reset: ## Reset database (drops and recreates)
	docker-compose down -v
	docker-compose up -d postgres
	@echo "Waiting for database to be ready..."
	@sleep 3
	$(MAKE) migrate

.PHONY: install
install: ## Install dependencies
	go mod download
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: generate
generate: ## Generate SQLC code
	sqlc generate

.PHONY: migrate
migrate: ## Run database migrations
	go run main.go migrate

.PHONY: build
build: ## Build the application
	go build -o bin/app main.go

.PHONY: test
test: ## Run tests
	go test -v ./...

.PHONY: test-auth
test-auth: ## Test authentication endpoints
	@echo "Testing registration..."
	@curl -X POST http://localhost:3000/api/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"test@example.com","username":"testuser","password":"Password123!"}' \
		| jq .
	@echo "\nTesting login..."
	@curl -X POST http://localhost:3000/api/auth/login \
		-H "Content-Type: application/json" \
		-d '{"email_or_username":"test@example.com","password":"Password123!"}' \
		| jq .

.PHONY: test-security
test-security: ## Test security features
	@echo "Testing rate limiting..."
	@for i in {1..70}; do \
		curl -s -o /dev/null -w "Request $$i: %{http_code}\n" \
		http://localhost:3000/api/auth/login \
		-H "Content-Type: application/json" \
		-d '{"email_or_username":"test","password":"wrong"}'; \
	done
	@echo "\nTesting account lockout..."
	@for i in {1..6}; do \
		echo "Failed login attempt $$i:"; \
		curl -X POST http://localhost:3000/api/auth/login \
		-H "Content-Type: application/json" \
		-d '{"email_or_username":"test@example.com","password":"wrongpassword"}' \
		| jq -r '.error'; \
	done

.PHONY: test-password-validation
test-password-validation: ## Test password validation
	@echo "Testing weak passwords..."
	@echo "Too short:"
	@curl -X POST http://localhost:3000/api/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"weak1@example.com","username":"weak1","password":"123"}' \
		| jq -r '.error'
	@echo "No uppercase:"
	@curl -X POST http://localhost:3000/api/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"weak2@example.com","username":"weak2","password":"password123"}' \
		| jq -r '.error'
	@echo "No numbers:"
	@curl -X POST http://localhost:3000/api/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"weak3@example.com","username":"weak3","password":"Password"}' \
		| jq -r '.error'

.PHONY: lint
lint: ## Run linter
	golangci-lint run

.PHONY: security-scan
security-scan: ## Run security scanning
	@echo "Running gosec security scanner..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Installing..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi

.PHONY: audit-deps
audit-deps: ## Audit dependencies for vulnerabilities
	@echo "Checking for known vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Installing..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf internal/database/sqlc/*.go

.PHONY: setup
setup: install up ## Initial setup (install deps and start services)
	@echo "Waiting for database to be ready..."
	@sleep 5
	$(MAKE) generate
	$(MAKE) migrate
	@echo "Setup complete! Run 'make dev' to start the application."

.PHONY: prod
prod: ## Start production server
	go run main.go prod

.PHONY: security-check
security-check: lint security-scan audit-deps ## Run all security checks

.PHONY: benchmark-auth
benchmark-auth: ## Benchmark authentication endpoints
	@echo "Benchmarking login endpoint..."
	@if command -v wrk >/dev/null 2>&1; then \
		echo '{"email_or_username":"test@example.com","password":"Password123!"}' > /tmp/login.json; \
		wrk -t2 -c10 -d30s -s /tmp/login.json http://localhost:3000/api/auth/login; \
		rm /tmp/login.json; \
	else \
		echo "wrk not installed. Please install wrk for benchmarking."; \
	fi

.PHONY: config-check
config-check: ## Check configuration security
	@echo "Checking security configuration..."
	@echo "JWT Secret set: $$(if [ -n "$$JWT_SECRET" ]; then echo "✓"; else echo "✗ Missing JWT_SECRET"; fi)"
	@echo "BCrypt Cost: $$(printenv AUTH_BCRYPT_COST || echo "12 (default)")"
	@echo "Rate Limiting: $(printenv SECURITY_RATE_LIMIT_REQUESTS || echo "60 (default)")"
	@echo "Password Min Length: $(printenv AUTH_PASSWORD_MIN_LENGTH || echo "8 (default)")"
	@echo "Max Login Attempts: $(printenv AUTH_MAX_LOGIN_ATTEMPTS || echo "5 (default)")"
	@echo "Lockout Duration: $(printenv AUTH_LOCKOUT_DURATION || echo "15m (default)")"

.PHONY: create-admin
create-admin: ## Create admin user (interactive)
	@echo "Creating admin user..."
	@read -p "Enter admin email: " email; \
	read -p "Enter admin username: " username; \
	read -s -p "Enter admin password: " password; \
	echo; \
	curl -X POST http://localhost:3000/api/auth/register \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"$email\",\"username\":\"$username\",\"password\":\"$password\",\"role\":\"admin\"}" \
		| jq .

.PHONY: show-audit-logs
show-audit-logs: ## Show recent audit logs (requires admin token)
	@read -p "Enter admin access token: " token; \
	curl -H "Authorization: Bearer $token" \
		http://localhost:3000/api/auth/audit-logs \
		| jq .

.PHONY: show-security-stats
show-security-stats: ## Show security statistics (requires admin token)
	@read -p "Enter admin access token: " token; \
	curl -H "Authorization: Bearer $token" \
		http://localhost:3000/api/auth/security-stats \
		| jq .