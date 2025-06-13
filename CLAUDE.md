# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend (Go)
- `make setup` - Initial setup: install dependencies and start services
- `make dev` - Start development server (Go runs directly, not via Docker)
- `make prod` - Start production server
- `make build` - Build the Go application
- `make test` - Run Go tests
- `make lint` - Run golangci-lint
- `make generate` - Generate SQLC code from database queries

### Frontend (SvelteKit)
- `cd frontend && npm run dev` - Start frontend development server (localhost:5173)
- `cd frontend && npm run build` - Build production frontend
- `cd frontend && npm run check` - TypeScript and Svelte checking
- `cd frontend && npm run lint` - ESLint and Prettier linting

### Database
- `make up` - Start PostgreSQL via docker-compose
- `make down` - Stop all docker services
- `make migrate` - Run database migrations
- `make db-psql` - Connect to database with psql
- `make db-reset` - Reset database (drops and recreates)

### Security Testing
- `make security-check` - Run comprehensive security checks (lint, security scan, audit deps)
- `make test-security` - Test rate limiting and security features
- `make test-auth` - Test authentication endpoints

## Architecture Overview

### Go Backend Structure
- **main.go** - Entry point, delegates to cmd package
- **cmd/** - CLI commands using Cobra (dev, prod, migrate)
- **internal/auth/** - Complete authentication system with JWT, sessions, password security
- **internal/middleware/** - Security middleware (CSRF, CSP, rate limiting, auth)
- **internal/database/** - SQLC-generated database code and migrations
- **internal/routes/** - HTTP routing and API endpoints
- **internal/services/** - Business logic services

### Frontend Structure (SvelteKit)
- **src/routes/** - SvelteKit file-based routing
- **src/lib/components/** - Reusable Svelte components organized by domain
- **src/lib/stores/** - Svelte stores for state management
- **src/lib/api.ts** - API client for backend communication
- **src/lib/csrf.ts** - CSRF token handling

### Database Architecture
- PostgreSQL with UUID primary keys
- User authentication with security features (account lockout, password policies)
- Role-based access control (admin/user roles)
- Audit logging for security events
- SQLC for type-safe database queries

### Security Features
- Comprehensive CSRF protection with token rotation
- Content Security Policy with nonce-based script execution  
- Rate limiting on authentication endpoints
- Account lockout after failed login attempts
- Password strength validation and secure hashing (bcrypt)
- Security headers and CORS configuration
- Audit logging for security events

### Development vs Production
- **Development**: CORS enabled for localhost:5173, relaxed security headers, frontend proxied
- **Production**: Static files embedded in Go binary, strict security headers, HTTPS enforcement

## Key Configuration Files
- **sqlc.yaml** - Database code generation configuration
- **go.mod** - Go dependencies and module definition
- **frontend/package.json** - Frontend dependencies and build scripts
- **docker-compose.yml** - PostgreSQL and pgAdmin services
- **Dockerfile** - Multi-stage build for production deployment

## Testing Strategy
- Unit tests for authentication timing attacks prevention
- Security testing via makefile targets
- Manual endpoint testing with curl commands in makefile
- Password validation testing scenarios

## Deployment
- Railway platform deployment ready
- TLS termination handled by Railway (application expects HTTP with X-Forwarded-Proto header)
- Multi-stage Docker build (Node.js frontend → Go backend → minimal runtime)
- Static assets embedded in Go binary for production
- Environment variable configuration via Viper