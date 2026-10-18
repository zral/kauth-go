# Prosjekttillegg: dark-factory-expert (kauth-go)

- **Risiko:** en feil i token-utstedelse, refresh-rotasjon eller service-resolveren kan låse ute alle brukere på alle tjenester, eller verre — slippe feil bruker inn i feil tjeneste. Identitetsinfrastruktur har høyere risiko per linje enn nesten all annen kode.
- **Prod er samme maskin som utviklingsmiljøet:** `make build` + `sudo systemctl restart kauth`, helsesjekk mot `/.well-known/openid-configuration`. Et autonomt deploy-steg rammer innlogging i alle tjenester.
- **Supply chain:** dependency-guard ved nye Go-moduler, `govulncheck`, og krav om CGO-fri bygg.
- **Drift utenfor deploy:** backup-cron (03:00), cleanup-jobben og helsesjekker finnes, men ingen loop fra en produksjonsfeil tilbake til prosessen.
- DSF-filene versjoneres i et privat repo (`dsf`-aliaset, se CLAUDE.md) — ta med det i vurderinger av artefakt-flyt og audit trail.
- Prosjektets egne skills som også evalueres: `kauth-ux`, `product-owner`, `humanizer`, `perf-audit`, `dependency-guard`.
