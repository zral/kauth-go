-- +goose Up
-- Auditloggen filtreres nå på hendelsestype fra admin-panelet, både i
-- listevisningen og i tellingen bak pagineringen. Uten indeks blir det
-- full tabellskanning på en tabell som vokser med hver innlogging.
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

-- +goose Down
DROP INDEX IF EXISTS idx_audit_events_type;
