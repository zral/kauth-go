-- +goose Up
-- Auditloggen har to skrivemåter for samme innloggingsmetode: 9 rader fra
-- 16. juni 2026 bruker 'magic-link', resten 'magic_link'. Gjeldende kode
-- skriver bare understrek-varianten (auth/magic.go), så bindestrek-radene er
-- etterlatt data fra en tidligere versjon. To varianter gir to separate
-- avkryssingsbokser i auditloggens metodefilter.
UPDATE audit_events SET auth_method = 'magic_link' WHERE auth_method = 'magic-link';

-- +goose Down
-- Ikke reverserbar: hvilke rader som opprinnelig hadde bindestrek er ikke
-- bevart noe sted. Bevisst no-op framfor å gjette.
SELECT 1;
