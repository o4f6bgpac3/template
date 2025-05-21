# Use a multi-stage build
FROM node:18 AS frontend-builder
WORKDIR /build
# Copy frontend source code
COPY frontend/ ./frontend/
# Build frontend
WORKDIR /build/frontend
RUN npm install && npm run prebuild && npm run build

FROM golang:1.24-bullseye AS app-builder
WORKDIR /build
# Copy Go source code
COPY . .
# Copy the built frontend from the previous stage
COPY --from=frontend-builder /build/frontend/build ./frontend/build

# Build the Go application (without the git variables)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags release,viper_bind_struct -a \
    -ldflags="-s -w" \
    -o application

# Final stage - minimal runtime image
FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl procps file \
  && rm -rf /var/lib/apt/lists/*

# Copy only the built application from the builder stage
COPY --from=app-builder /build/application ./application

RUN chmod +x ./application

ENV PORT=8080
EXPOSE 8080

CMD ["./application", "prod"]