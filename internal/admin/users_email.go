package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
	"modernc.org/sqlite"
)

// Feil som gjør at e-postendringen avvises uten skriving. Hver har en fast
// tekst og en statuskode; rå feiltekst fra databasen når aldri svaret.
var (
	errEmailSame       = errors.New("samme adresse")
	errEmailTaken      = errors.New("adressen er i bruk")
	errEmailConcurrent = errors.New("endret samtidig")
)

// emailTimeFormat er formatet token.ParseEpoch leser. Epoken og magic-tokens'
// expires_at bruker det samme, så strengsammenligningen i SQL og tolkingen i
// dispatch/middleware ser den samme verdien.
const emailTimeFormat = "2006-01-02T15:04:05Z"

// HandleEmailChange bytter brukerens e-postadresse. Sesjoner revokeres og
// ubrukte magic-lenker brennes i samme transaksjon, ellers kunne en gammel
// lenke eller et gammelt token følge adressen til den nye eieren.
func (h *UsersHandler) HandleEmailChange(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	user, err := h.queries.GetUserByID(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	_ = r.ParseForm()
	formEmail := r.PostFormValue("email")
	newEmail := token.NormalizeEmail(formEmail)
	if !token.ValidEmail(newEmail) {
		h.renderEmailError(w, r, user, formEmail, http.StatusUnprocessableEntity, "Skriv inn en gyldig e-postadresse.")
		return
	}
	// Avkrysningen sjekkes her og ikke bare med required i malen: et skjema
	// postet uten nettleser skal ikke hoppe over avtalen med tjenesteeierne.
	if r.PostFormValue("confirm") != "1" {
		h.renderEmailError(w, r, user, formEmail, http.StatusUnprocessableEntity, "Bekreft at endringen er avtalt med tjenesteeierne.")
		return
	}

	// WithoutCancel: revokeringen og brenningen hører til endringen og skal ikke
	// kunne stoppes halvveis av at admin kobler fra.
	ctx := context.WithoutCancel(r.Context())
	now := time.Now().UTC().Format(emailTimeFormat)
	var oldEmail string
	var revoked, burned, invitesBurned int64
	err = token.RunInTx(ctx, h.sqlDB, func(q *gen.Queries) error {
		// Revokeringen kommer først: det er en skriving, så transaksjonen tar
		// skrivelåsen før den leser. Leser den først og skriver etterpå, kan en
		// samtidig skriver gi SQLITE_BUSY_SNAPSHOT i stedet for en ren 409.
		reason := "email_changed"
		var err error
		revoked, err = q.RevokeUserRefreshTokens(ctx, gen.RevokeUserRefreshTokensParams{
			RevokedReason: &reason,
			UserID:        &id,
		})
		if err != nil {
			return err
		}
		cur, err := q.GetUserByID(ctx, id)
		if err != nil {
			return err
		}
		oldEmail = cur.Email
		if token.NormalizeEmail(oldEmail) == newEmail {
			return errEmailSame
		}
		// Sjekk og skriving er én setning: gammel e-post i vilkåret og
		// unik-indeksen avgjør, ikke en forhåndssjekk.
		n, err := q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{
			NewEmail:       newEmail,
			EmailChangedAt: &now,
			ID:             id,
			OldEmail:       oldEmail,
		})
		if err != nil {
			var se *sqlite.Error
			if errors.As(err, &se) && (se.Code() == 2067 || se.Code() == 1555) { // UNIQUE / PRIMARYKEY
				return errEmailTaken
			}
			return err
		}
		if n != 1 {
			return errEmailConcurrent
		}
		// Magic-tokens lagres på normalisert e-post.
		burned, err = q.BurnMagicTokensForEmails(ctx, gen.BurnMagicTokensForEmailsParams{
			OldEmail: token.NormalizeEmail(oldEmail),
			NewEmail: newEmail,
			Now:      now,
		})
		if err != nil {
			return err
		}
		// K26: en invitasjon er bundet til adressen den ble laget for. Lenken ligger
		// i den gamle innboksen, og den skal ikke lenger kunne brukes etter byttet.
		invitesBurned, err = q.BurnLinkInvitesForUser(ctx, gen.BurnLinkInvitesForUserParams{
			Now: token.FormatLinkInviteTime(time.Now()), UserID: id,
		})
		return err
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case errors.Is(err, errEmailSame):
		h.renderEmailError(w, r, user, formEmail, http.StatusUnprocessableEntity, "Det er allerede brukerens adresse.")
		return
	case errors.Is(err, errEmailTaken):
		h.renderEmailError(w, r, user, formEmail, http.StatusConflict, "Adressen er i bruk av en annen bruker.")
		return
	case errors.Is(err, errEmailConcurrent):
		// Brukeren er endret av en annen: vis den nåværende adressen, ikke den vi leste først.
		if fresh, ferr := h.queries.GetUserByID(r.Context(), id); ferr == nil {
			user = fresh
		}
		h.renderEmailError(w, r, user, formEmail, http.StatusConflict, "Brukeren ble endret samtidig. Prøv igjen.")
		return
	case err != nil:
		slog.Error("admin: e-postendring feilet", "id", id, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:    "user_email_changed",
		Email:   newEmail,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d old=%q revoked=%d burned=%d invites_burned=%d", id, oldEmail, revoked, burned, invitesBurned),
	})
	if !auditOK {
		http.Redirect(w, r, usersRedirect(false), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d/edit", id), http.StatusSeeOther)
}

// renderEmailError viser redigeringssiden på nytt med feilen og identitetene.
func (h *UsersHandler) renderEmailError(w http.ResponseWriter, r *http.Request, user gen.User, formEmail string, status int, msg string) {
	data, err := h.editData(r.Context(), user)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	data["EmailError"] = msg
	data["FormNewEmail"] = formEmail
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = h.editTpl.Execute(w, data)
}
