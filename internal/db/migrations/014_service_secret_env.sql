-- +goose Up
-- Klienthemmeligheter som miljøvariabel-referanse (017): en tjeneste kan peke på
-- navnet på en env-variabel i stedet for å lagre Google/Microsoft-hemmeligheten
-- i klartekst i databasen. Verdien lagres aldri her, bare navnet.

-- Bare navn med prefikset KAUTH_SVC_ kan refereres, så en rad ikke kan peke på
-- KAUTH_PRIVATE_KEY_PEM, KAUTH_IDP_* eller andre interne hemmeligheter. Samme
-- forsvar i dybden som client_secret_env i 012: lastevalideringen i admin er
-- autoritativ, men en rad satt inn for hånd med sqlite3 avvises av databasen.
-- Små bokstaver og tegn utenfor [A-Z0-9_] avvises, siden navnet slås opp
-- ordrett i miljøet.
-- De gamle kolonnene google_client_secret/microsoft_client_secret røres ikke:
-- de er fortsatt reserven til hemmelighetene er flyttet i drift.
ALTER TABLE services ADD COLUMN google_client_secret_env TEXT
    CHECK (google_client_secret_env IS NULL OR
           (google_client_secret_env GLOB 'KAUTH_SVC_[A-Z0-9_]*'
            AND google_client_secret_env NOT GLOB '*[^A-Z0-9_]*'));
ALTER TABLE services ADD COLUMN microsoft_client_secret_env TEXT
    CHECK (microsoft_client_secret_env IS NULL OR
           (microsoft_client_secret_env GLOB 'KAUTH_SVC_[A-Z0-9_]*'
            AND microsoft_client_secret_env NOT GLOB '*[^A-Z0-9_]*'));

-- +goose Down
-- Krever SQLite 3.35 eller nyere. Kolonnene inneholder bare referanser, så
-- ingen hemmeligheter går tapt; verdiene i de gamle kolonnene er uendret.
ALTER TABLE services DROP COLUMN microsoft_client_secret_env;
ALTER TABLE services DROP COLUMN google_client_secret_env;
