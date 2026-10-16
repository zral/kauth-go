-- name: ListActiveIdentityProviders :many
SELECT * FROM identity_providers WHERE active = 1 ORDER BY slug;

-- Only active providers on active services, in login page order: position,
-- then slug as a stable tiebreaker. (ASCII only: sqlc offset bug.)
-- name: ListServiceIdentityProviders :many
SELECT sip.service_id, sip.provider_id, sip.position
FROM service_identity_providers sip
JOIN identity_providers ip ON ip.id = sip.provider_id
JOIN services s ON s.id = sip.service_id
WHERE ip.active = 1 AND s.active = 1
ORDER BY sip.service_id, sip.position, ip.slug;
