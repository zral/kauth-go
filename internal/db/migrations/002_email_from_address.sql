-- +goose Up
-- BACKLOG F21: magic-link-e-post sendes fra én global avsenderadresse
-- (KAUTH_SMTP_FROM=noreply@klarsyn.net) for alle tjenester, uansett merkevare.
-- Nullable per-tjeneste override, samme mønster som auth_host — NULL betyr
-- uendret oppførsel (global SMTPFrom via rå SMTP), satt betyr sending via
-- Brevo med denne adressen som avsender (krever domenet er Brevo-verifisert).
ALTER TABLE services ADD COLUMN email_from_address TEXT;

-- Setter Spektos adresse i samme migrasjon (ikke en separat manuell UPDATE
-- etter deploy): service.Registry cacher alle tjenester i minnet ved
-- oppstart (Warmup), så en UPDATE kjørt etter at prosessen allerede har
-- startet ville krevd en ny restart for å bli synlig. Migrasjoner kjører
-- FØR Warmup ved samme oppstart, så denne verdien er korrekt fra første
-- request uten et ekstra driftsvindu. spekto.live er bekreftet
-- Brevo-verifisert (DNS-autentisert) i kontoen kauth-instansen deler med
-- POV-appens egen Brevo-sending (ADN 65) — de fire andre tjenestene er det
-- ikke, og beholder derfor uendret rå SMTP (NULL).
UPDATE services SET email_from_address = 'noreply@spekto.live' WHERE id = 'spekto';

-- +goose Down
ALTER TABLE services DROP COLUMN email_from_address;
