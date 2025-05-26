package middleware

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/unrolled/secure"
)

func Setup(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	secureMiddleware := secure.New(secure.Options{
		AllowedHosts:                  cfg.Config.HTTP.Hosts,
		HostsProxyHeaders:             []string{"X-Forwarded-Hosts"},
		SSLRedirect:                   true,
		SSLHost:                       cfg.Config.HTTP.BaseURL,
		SSLProxyHeaders:               map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:                    31536000, // 1 year
		STSIncludeSubdomains:          true,
		STSPreload:                    true,
		FrameDeny:                     true,
		ContentTypeNosniff:            true,
		BrowserXssFilter:              true,
		ContentSecurityPolicy:         "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
		ReferrerPolicy:                "strict-origin-when-cross-origin",
		PermissionsPolicy:             "fullscreen=(), geolocation=()",
		CrossOriginOpenerPolicy:       "same-origin",
		CrossOriginEmbedderPolicy:     "require-corp",
		CrossOriginResourcePolicy:     "same-origin",
		XDNSPrefetchControl:           "off",
		XPermittedCrossDomainPolicies: "none",
		IsDevelopment:                 false,
	})
	r.Use(secureMiddleware.Handler)
}
