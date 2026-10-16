-- Comments above queries must be ASCII only: sqlc has an offset bug that
-- corrupts the generated SQL otherwise.

-- name: ListActiveIdentityProviders :many
SELECT * FROM identity_providers WHERE active = 1 ORDER BY slug;

-- Only active providers on active services, in login page order: position,
-- then slug as a stable tiebreaker.
-- name: ListServiceIdentityProviders :many
SELECT sip.service_id, sip.provider_id, sip.position
FROM service_identity_providers sip
JOIN identity_providers ip ON ip.id = sip.provider_id
JOIN services s ON s.id = sip.service_id
WHERE ip.active = 1 AND s.active = 1
ORDER BY sip.service_id, sip.position, ip.slug;

-- All providers including inactive, for the admin overview.
-- name: ListAllIdentityProviders :many
SELECT * FROM identity_providers ORDER BY slug;

-- All assignments with slug for display, regardless of active flags.
-- name: ListServiceIdentityProvidersAll :many
SELECT sip.service_id, sip.provider_id, sip.position, ip.slug
FROM service_identity_providers sip
JOIN identity_providers ip ON ip.id = sip.provider_id
ORDER BY sip.service_id, sip.position, ip.slug;

-- name: ListAssignmentsForService :many
SELECT sip.service_id, sip.provider_id, sip.position, ip.slug
FROM service_identity_providers sip
JOIN identity_providers ip ON ip.id = sip.provider_id
WHERE sip.service_id = sqlc.arg(service_id)
ORDER BY sip.position, ip.slug;

-- name: DeleteServiceIdentityProviders :exec
DELETE FROM service_identity_providers WHERE service_id = sqlc.arg(service_id);

-- name: InsertServiceIdentityProvider :exec
INSERT INTO service_identity_providers (service_id, provider_id, position)
VALUES (sqlc.arg(service_id), sqlc.arg(provider_id), sqlc.arg(position));

-- Issuer to name lookup for the identity list.
-- name: ListIdentityProviderNames :many
SELECT issuer, display_name, slug FROM identity_providers ORDER BY slug;
