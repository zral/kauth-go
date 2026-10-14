package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// Token — POST /token. Dispatcher på grant_type (RFC 6749 §4).
// Ingen grant_type (eldre klienter) behandles som refresh_token for
// bakoverkompatibilitet.
func (h *PasswordHandlers) Token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("grant_type") == "authorization_code" {
		h.authorizationCodeGrant(w, r)
		return
	}
	h.RefreshToken(w, r)
}

// authorizationCodeGrant løser inn en autorisasjonskode fra /login
// (RFC 6749 §4.1.3 + PKCE, RFC 7636 §4.6).
func (h *PasswordHandlers) authorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	verifier := r.FormValue("code_verifier")
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// RFC 7636 §4.1: 43-128 tegn. En kortere/lengre verdi er aldri gyldig —
	// avvis før vi i det hele tatt bruker den, samme prinsipp som å ikke
	// hashe et opplagt for kort passord.
	if len(verifier) < 43 || len(verifier) > 128 {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	codeHash := token.HashOpaque(code)
	row, err := h.queries.GetAuthorizationCodeByHash(r.Context(), codeHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_invalid", ServiceID: sanitizeLogValue(clientID), IP: ip, UA: ua, Success: false})
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		slog.Error("authorization_code: oppslag feilet", "err", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	// Klassifisering FØR konsum: en feil klient, redirect_uri eller verifier
	// skal ikke brenne en kode som den rette klienten fortsatt kan løse inn (K21).
	if h.rejectCode(w, r, row, clientID, redirectURI, verifier, ip, ua) {
		return
	}

	svc := h.reg.Resolve("", row.ServiceID, "")
	if svc == nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client")
		return
	}

	user, err := h.activeSessionUser(r.Context(), row.UserID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("authorization_code: brukeroppslag feilet", "err", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	// Forsvar i dybden: /dispatch binder koden til tokenets aud (nivå 0 krever
	// aud == client_id og et ferskt token), så et B-token kan ikke lenger
	// veksles til en A-kode. Policyen for A evalueres likevel her, siden
	// rolle og org kan ha endret seg siden innloggingen, og fordi dette er
	// det eneste punktet som ikke avhenger av hva /dispatch fikk i URL-en.
	// Se PR-diskusjonen (github.com/zral/kauth-go/pull/1).
	if err := checkPolicy(user, svc); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_policy_denied", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	nonce := ""
	if row.Nonce != nil {
		nonce = *row.Nonce
	}
	scope := ""
	if row.Scope != nil {
		scope = *row.Scope
	}

	// Tokens som kan feile signeres før koden konsumeres, slik at en intern
	// feil ikke brenner koden.
	atIssued, err := h.issuer.IssueAccessDetailed(user, *svc)
	if err != nil {
		slog.Error("authorization_code: utstedelse av access-token feilet", "err", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	at := atIssued.Token
	// id_token er en OIDC-ting (OIDC Core §3.1.3.3): utstedes kun når
	// openid-scopet faktisk ble bedt om. En ren OAuth2-klient som aldri ba
	// om openid skal ikke få et identitetstoken den ikke forventer.
	idToken, jtiID := "", "-"
	if scopeContains(scope, "openid") {
		idIssued, err := h.issuer.IssueIDTokenDetailed(user, *svc, nonce)
		if err != nil {
			slog.Error("authorization_code: utstedelse av id_token feilet", "err", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		idToken, jtiID = idIssued.Token, idIssued.JTI
	}

	rt, family, err := h.refresh.RedeemAuthorizationCode(r.Context(), token.CodeRedemption{
		CodeHash:      codeHash,
		ServiceID:     clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: S256Challenge(verifier),
	}, user, *svc, ip, ua)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("authorization_code: innløsning feilet", "err", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		// SQLITE_BUSY hos taperen gir 500 uten reuse-klassifisering: akseptert,
		// K23 krever høyst én vinner, ikke at hver taper blir klassifisert.
		// Tapt kappløp: en annen forespørsel konsumerte koden mellom lesingen og
		// UPDATE-en. Les på nytt, så taperen behandles som gjenbruk og vinnerens
		// familie revokeres (K23).
		fresh, rerr := h.queries.GetAuthorizationCodeByHash(r.Context(), codeHash)
		if rerr != nil {
			if errors.Is(rerr, sql.ErrNoRows) {
				h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_invalid", ServiceID: row.ServiceID, IP: ip, UA: ua, Success: false})
				writeTokenError(w, http.StatusBadRequest, "invalid_grant")
				return
			}
			slog.Error("authorization_code: omlesing feilet", "err", rerr)
			writeTokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if !h.rejectCode(w, r, fresh, clientID, redirectURI, verifier, ip, ua) {
			h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_invalid", ServiceID: row.ServiceID, IP: ip, UA: ua, Success: false})
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		}
		return
	}

	// jti og familie lar en lekket token spores til innløsningen.
	h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_exchanged", AuthMethod: "authorization_code", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true,
		Details: fmt.Sprintf("jti_access=%s jti_id=%s family=%s", atIssued.JTI, jtiID, family)})

	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 15 * time.Minute
	}
	resp := map[string]any{
		"access_token":  at,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// activeSessionUser finner brukeren en refresh-rad eller kode tilhører, bare via
// user_id. En rad uten user_id (ingen e-postmatch ved migrering) behandles som
// «ingen aktiv bruker»: en e-post-fallback ville bundet en gammel familie til
// en senere opprettet konto med samme adresse (011 PD13, sikkerhetsvurdering M2).
func (h *PasswordHandlers) activeSessionUser(ctx context.Context, userID *int64) (gen.User, error) {
	if userID == nil {
		return gen.User{}, sql.ErrNoRows
	}
	return h.queries.GetActiveUserByID(ctx, *userID)
}

// rejectCode skriver 400 invalid_grant og returnerer true når koden ikke kan
// løses inn. Raden røres bare ved gjenbruk (revokering av familien); mismatch
// og utløp lar den stå, så den rette klienten kan løse den inn.
func (h *PasswordHandlers) rejectCode(w http.ResponseWriter, r *http.Request, row gen.AuthorizationCode, clientID, redirectURI, verifier, ip, ua string) bool {
	event := func(typ, details string) {
		h.aud.Log(r.Context(), audit.Event{Type: typ, Email: row.Email, ServiceID: row.ServiceID, Details: details, IP: ip, UA: ua, Success: false})
	}
	switch {
	case row.Used == 1:
		// Revoker bare når kalleren beviser at den kjenner koden hele veien
		// (client, redirect_uri og verifier). Ellers kunne alle med en lekket
		// kode logge ut brukeren uten verifier.
		if row.ServiceID != clientID || row.RedirectUri != redirectURI || !VerifyPKCE(verifier, row.CodeChallenge, row.CodeChallengeMethod) {
			event("authorization_code_reuse", "reason=unverified")
			break
		}
		details := ""
		if row.FamilyID != nil {
			details = "family=" + *row.FamilyID
		}
		// WithoutCancel: revokeringen skal fullføres selv om klienten kobler fra,
		// ellers overlever angriperens (eller vinnerens) familie.
		if row.FamilyID != nil {
			if err := h.refresh.RevokeFamily(context.WithoutCancel(r.Context()), *row.FamilyID, "authorization_code_reuse"); err != nil {
				details += " revoke_failed"
			}
		}
		event("authorization_code_reuse", details)
	case row.ExpiresAt <= time.Now().UTC().Format("2006-01-02T15:04:05Z"):
		event("authorization_code_invalid", "")
	case row.ServiceID != clientID:
		event("authorization_code_mismatch", "reason=client")
	case row.RedirectUri != redirectURI:
		event("authorization_code_mismatch", "reason=redirect_uri")
	// PKCE er obligatorisk for enhver kode utstedt via denne flyten, uten
	// per-tjeneste unntak (migrasjon 007: code_challenge er NOT NULL).
	case !VerifyPKCE(verifier, row.CodeChallenge, row.CodeChallengeMethod):
		event("authorization_code_mismatch", "reason=pkce")
	default:
		return false
	}
	writeTokenError(w, http.StatusBadRequest, "invalid_grant")
	return true
}

// scopeContains sjekker om et mellomromseparert scope-felt inneholder en
// eksakt scope-verdi (ikke substreng-match — "openidconnect" skal ikke
// telle som "openid").
func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// RefreshToken — POST /token
// Leser refresh token fra cookie FØR form-body (cookie prioriteres).
func (h *PasswordHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	// Origin-sjekk FØR Rotate: et avvist kall skal ikke brenne tokenet. Uten
	// Origin-header (server-til-server) går kallet gjennom som før. En tom
	// Origin-header er en header som finnes, og avvises.
	if vals, present := r.Header["Origin"]; present {
		origin := ""
		if len(vals) > 0 {
			origin = vals[0]
		}
		if len(vals) > 1 || !OriginAllowed(h.corsOrigins, origin) {
			// Ingen CORS-headere på avvisningen, selv om en middleware skulle ha satt dem.
			for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
				w.Header().Del(k)
			}
			_ = r.ParseForm()
			logged := sanitizeLogValue(strings.Join(vals, ","))
			slog.Warn("refresh avvist: origin", "origin", logged, "ip", ip)
			// Audit bare når et refresh-token faktisk er presentert, slik at
			// anonyme kall ikke gir DB-skriving.
			if c, err := r.Cookie("refresh_token"); (err == nil && c.Value != "") || r.PostFormValue("refresh_token") != "" {
				h.aud.Log(r.Context(), audit.Event{Type: "refresh_invalid_origin", Details: "origin=" + logged, IP: ip, UA: ua, Success: false})
			}
			writeTokenError(w, http.StatusForbidden, "invalid_origin")
			return
		}
	}
	_ = r.ParseForm()

	plain := ""
	if c, err := r.Cookie("refresh_token"); err == nil {
		plain = c.Value
	}
	if plain == "" {
		plain = r.FormValue("refresh_token")
	}
	if plain == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	result, err := h.refresh.Rotate(r.Context(), plain, ip, ua)
	if err != nil {
		if !errors.Is(err, token.ErrTokenReuse) && !errors.Is(err, token.ErrTokenRevoked) {
			// Intern feil (DB): klienten har ikke gjort noe galt og beholder cookien.
			slog.Error("refresh: rotasjon feilet", "err", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		clearCookie(w, "refresh_token")
		if errors.Is(err, token.ErrTokenReuse) {
			writeTokenError(w, http.StatusUnauthorized, "refresh_token_reused")
			return
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	// WithoutCancel: revokering skal fullføres selv om klienten kobler fra,
	// ellers kan barnet fra rotasjonen overleve.
	revokeCtx := context.WithoutCancel(r.Context())

	user, err := h.activeSessionUser(r.Context(), result.UserID)
	if err != nil {
		// Rotasjonen har allerede laget et barn; det må ikke overleve en deaktivert bruker.
		// Forbigående DB-feil revokerer ikke, så brukeren slipper ny innlogging for SQLITE_BUSY.
		if errors.Is(err, sql.ErrNoRows) {
			h.refresh.RevokeFamily(revokeCtx, result.FamilyID, "user_inactive")
			h.aud.Log(r.Context(), audit.Event{Type: "refresh_user_inactive", Email: result.Email, ServiceID: result.ServiceID, IP: ip, UA: ua, Success: false})
			clearCookie(w, "refresh_token")
		} else {
			slog.Error("refresh: brukeroppslag feilet", "err", err)
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	// Tjenesten lagret på raden er autoritativ; service_id fra klienten er bare et hint.
	// Avvisning på tjeneste eller policy revokerer familien, så barnet fra rotasjonen blir ubrukelig.
	deny := func(eventType, reason, details string) {
		h.refresh.RevokeFamily(revokeCtx, result.FamilyID, reason)
		h.aud.Log(r.Context(), audit.Event{Type: eventType, Email: result.Email, ServiceID: result.ServiceID, Details: details, IP: ip, UA: ua, Success: false})
		clearCookie(w, "refresh_token")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
	}

	var svc *gen.Service
	if result.ServiceID != "" {
		svc = h.reg.Resolve("", result.ServiceID, "")
	}
	if svc == nil {
		deny("refresh_service_invalid", "service_invalid", "stored_service="+sanitizeLogValue(result.ServiceID))
		return
	}

	// Informativt event (Success: true): forespørselen innvilges for lagret tjeneste,
	// men avviket viser klienter som sender feil service_id.
	if given := r.FormValue("service_id"); given != "" && given != result.ServiceID {
		h.aud.Log(r.Context(), audit.Event{
			Type: "refresh_service_mismatch", Email: result.Email, ServiceID: result.ServiceID,
			Details: "stored=" + result.ServiceID + " given=" + sanitizeLogValue(given),
			IP:      ip, UA: ua, Success: true,
		})
	}

	if err := checkPolicy(user, svc); err != nil {
		deny("refresh_policy_denied", "policy_denied", err.Error())
		return
	}

	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		// Barnet fra rotasjonen ville ellers overleve, og neste forsøk utløse reuse-deteksjon.
		slog.Error("refresh: utstedelse av access-token feilet", "err", err)
		h.refresh.RevokeFamily(revokeCtx, result.FamilyID, "issue_failed")
		clearCookie(w, "refresh_token")
		writeTokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	setAuthCookies(w, svc, at, result.NewToken)

	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  at,
		"refresh_token": result.NewToken,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	})
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// sanitizeLogValue fjerner kontrolltegn og kutter til 200 tegn; verdien er
// klientstyrt (Origin, service_id) og havner i logg og audit.
func sanitizeLogValue(o string) string {
	o = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, o)
	if len(o) > 200 {
		o = o[:200]
	}
	return strings.ToValidUTF8(o, "")
}
