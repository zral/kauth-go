-- +goose Up
-- 108 auditrader fra 1.–16. juni 2026 har en kommaseparert tjenesteliste i
-- service_id der det skal stå én tjeneste-ID. De kom fra H2-migreringen, som
-- kopierte kolonnen rått (scripts/migrate-h2/main.go); kilden hadde en helt
-- annen betydning i det feltet. Gjeldende kode skriver alltid svc.ID, én
-- rad-ID, så ingen kodesti kan produsere dette.
--
-- Lista kastes ikke — den flyttes til details, som er NULL på alle radene.
-- service_id settes til NULL: hvilken tjeneste hendelsen gjaldt er ukjent,
-- og NULL er den ærlige representasjonen av det.
UPDATE audit_events
SET details    = COALESCE(details || ' | ', '') || 'H2-tjenesteliste: ' || service_id,
    service_id = NULL
WHERE service_id LIKE '%,%';

-- +goose Down
-- Ikke reverserbar uten å parse teksten tilbake. Bevisst no-op.
SELECT 1;
