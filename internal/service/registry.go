package service

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/zral/kauth-go/internal/db/gen"
)

type Registry struct {
	mu      sync.RWMutex
	cache   []gen.Service
	queries *gen.Queries
}

func NewRegistry(queries *gen.Queries) *Registry {
	return &Registry{queries: queries}
}

func (r *Registry) Warmup(ctx context.Context) error {
	services, err := r.queries.ListActiveServices(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cache = services
	r.mu.Unlock()
	return nil
}

func (r *Registry) Invalidate(ctx context.Context) error {
	return r.Warmup(ctx)
}

// Resolve finner tjeneste basert på host-header, service-ID eller redirect-URI.
// Returnerer nil hvis ingen match — caller bruker da default.
func (r *Registry) Resolve(host, serviceID, redirectURI string) *gen.Service {
	r.mu.RLock()
	services := r.cache
	r.mu.RUnlock()

	// 1. Host-header mot auth_host
	if host != "" {
		hostLc := strings.ToLower(host)
		for i := range services {
			if services[i].AuthHost != nil &&
				strings.ToLower(*services[i].AuthHost) == hostLc {
				svc := services[i]
				return &svc
			}
		}
	}

	// 2. Eksplisitt service-ID
	if serviceID != "" {
		for i := range services {
			if services[i].ID == serviceID {
				svc := services[i]
				return &svc
			}
		}
	}

	// 3. redirect_uri host mot domain (lengste match vinner)
	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err == nil && u.Host != "" {
			hostLc := strings.ToLower(u.Host)
			var best *gen.Service
			for i := range services {
				domLc := strings.ToLower(services[i].Domain)
				if hostLc == domLc || strings.HasSuffix(hostLc, "."+domLc) {
					if best == nil || len(domLc) > len(strings.ToLower(best.Domain)) {
						svc := services[i]
						best = &svc
					}
				}
			}
			if best != nil {
				return best
			}
		}
	}

	return nil
}

// Default returnerer tjenesten med is_default=1, eller første aktive tjeneste.
func (r *Registry) Default() *gen.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := range r.cache {
		if r.cache[i].IsDefault == 1 {
			svc := r.cache[i]
			return &svc
		}
	}
	if len(r.cache) > 0 {
		svc := r.cache[0]
		return &svc
	}
	return nil
}

// ResolveOrDefault returnerer Resolve-resultat, eller Default som fallback.
func (r *Registry) ResolveOrDefault(host, serviceID, redirectURI string) *gen.Service {
	if svc := r.Resolve(host, serviceID, redirectURI); svc != nil {
		return svc
	}
	return r.Default()
}

// All returnerer pekere til kopier av alle tjenester i cache.
// mu.RLock er tilstrekkelig — read-only operasjon.
func (r *Registry) All() []*gen.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*gen.Service, len(r.cache))
	for i := range r.cache {
		s := r.cache[i] // kopier verdi slik at peker er stabil utenfor låsen
		result[i] = &s
	}
	return result
}

// IsAllowedCallback sjekker om uri matcher en av tjenestens registrerte callback-URLer.
func (r *Registry) IsAllowedCallback(svc *gen.Service, uri string) bool {
	if svc == nil || uri == "" {
		return false
	}
	for _, allowed := range strings.Split(svc.CallbackUrl, ",") {
		if strings.TrimSpace(allowed) == uri {
			return true
		}
	}
	return false
}
