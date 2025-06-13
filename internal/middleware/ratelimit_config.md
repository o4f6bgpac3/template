# Enhanced Rate Limiting Configuration

## Overview

The enhanced rate limiting system provides multi-layered protection against various attack vectors including brute force attacks, distributed attacks, and abuse.

## Features

### 1. **Multi-Layer Rate Limiting**
- **IP-based limiting**: Prevents attacks from single IPs
- **User-based limiting**: Prevents abuse from authenticated users across multiple IPs
- **Endpoint-specific limiting**: Different limits for different endpoints based on sensitivity

### 2. **Endpoint-Specific Configurations**

#### Login Endpoint (`/api/auth/login`)
- **IP Limit**: 5 attempts per 5 minutes
- **User Limit**: 3 attempts per 10 minutes
- **Rationale**: Most sensitive endpoint, requires strictest limits

#### Registration Endpoint (`/api/auth/register`)
- **IP Limit**: 3 registrations per 10 minutes  
- **User Limit**: 1 registration per hour
- **Rationale**: Prevents account creation abuse

#### Password Operations (`/api/auth/forgot-password`, `/api/auth/reset-password`, `/api/auth/change-password`)
- **IP Limit**: 3 operations per 15 minutes
- **User Limit**: 2 operations per 30 minutes
- **Rationale**: Password operations are sensitive and should be limited

#### Default Endpoints
- **IP Limit**: 20 requests per minute
- **User Limit**: 30 requests per minute
- **Rationale**: Reasonable limits for general API usage

## Implementation

### Usage in Routes

```go
// Replace basic rate limiting
r.Use(middleware.RateLimit(svc.RateLimitStore, requests, window))

// With enhanced rate limiting
r.Use(middleware.AuthSpecificRateLimit(svc.RateLimitStore))
```

### Custom Configuration

```go
config := middleware.RateLimitConfig{
    IPRequests:   5,                // Requests per IP
    IPWindow:     5 * time.Minute,  // Time window
    UserRequests: 3,                // Requests per user  
    UserWindow:   10 * time.Minute, // Time window
}

middleware := middleware.EnhancedRateLimit(store, config, "custom-endpoint")
```

## Security Benefits

### 1. **Distributed Attack Protection**
- User-based limiting prevents attackers from bypassing IP limits using multiple IPs
- Single compromised account can't be used to overwhelm the system

### 2. **Endpoint-Specific Protection** 
- Critical endpoints (login, password reset) have much stricter limits
- Prevents focused attacks on high-value targets

### 3. **Better Error Responses**
- JSON error responses instead of plain text
- Includes error type for better client handling
- Proper Retry-After headers

### 4. **Layered Defense**
- IP limiting catches basic attacks
- User limiting catches sophisticated distributed attacks
- Endpoint limiting provides context-aware protection

## Rate Limit Keys

The system uses structured keys to track different limit types:

- **IP limits**: `ip:{endpoint}:{client_ip}`
- **User limits**: `user:{endpoint}:{user_id}`

This ensures that limits are:
- Scoped to specific endpoints
- Isolated between different users/IPs
- Easy to monitor and debug

## Monitoring

Rate limit violations include:
- Error type: `rate_limit_exceeded`
- Limit type: IP vs User based
- Endpoint information
- Retry-After header for client guidance

## Future Enhancements

The system is designed to support:
- Progressive penalties for repeat offenders
- Dynamic rate limit adjustment based on threat level
- Integration with IP reputation services
- Custom rate limits per user role/tier