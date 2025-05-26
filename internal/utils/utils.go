package utils

import (
	"net/http"
	"net/netip"
)

func GetClientIp(r *http.Request) netip.Addr {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
