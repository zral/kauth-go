package service

import "github.com/zral/kauth-go/internal/db/gen"

// NewRegistryForTest lager en Registry med forhåndsfylt cache, uten database.
// Kun ment for testoppsett.
func NewRegistryForTest(services []gen.Service) *Registry {
	r := &Registry{}
	r.cache = services
	return r
}
