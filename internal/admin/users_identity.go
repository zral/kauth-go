package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// HandleUnlink kobler en identitet fra brukeren og revokerer brukerens
// refresh-familier i samme transaksjon. Revokeringen må følge med: uten den
// lever sesjonene til den frakoblede kontoen videre i opptil refresh-TTL.
func (h *UsersHandler) HandleUnlink(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	identityID, err := strconv.ParseInt(chi.URLParam(r, "identityID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// WithoutCancel: en klient som kobler fra midt i transaksjonen skal ikke
	// kunne etterlate en halv frakobling eller stoppe revokeringen.
	ctx := context.WithoutCancel(r.Context())
	var (
		del     gen.DeleteIdentityRow
		email   string
		revoked int64
	)
	err = token.RunInTx(ctx, h.sqlDB, func(q *gen.Queries) error {
		// Skrivingen kommer først: en deferred transaksjon som leser før den
		// skriver kan få SQLITE_BUSY_SNAPSHOT når en annen skriver rekker mellom.
		// user_id i vilkåret gjør at en identitet fra en annen bruker gir ingen rad.
		var err error
		del, err = q.DeleteIdentity(ctx, gen.DeleteIdentityParams{ID: identityID, UserID: id})
		if err != nil {
			return err
		}
		user, err := q.GetUserByID(ctx, id)
		if err != nil {
			return err
		}
		email = user.Email
		reason := "identity_unlinked"
		revoked, err = q.RevokeUserRefreshTokens(ctx, gen.RevokeUserRefreshTokensParams{
			RevokedReason: &reason,
			UserID:        &id,
		})
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("admin: frakobling av identitet feilet", "id", id, "identity", identityID, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	// Subject logges ikke: audit trenger å vite hvilken kontotype som ble borte,
	// ikke leverandørens stabile id for personen.
	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:    "identity_unlinked",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d identity=%d provider=%s issuer=%s admin_ok=%d revoked=%d",
			id, identityID, del.Provider, del.Issuer, del.AdminOk, revoked),
	})
	if !auditOK {
		http.Redirect(w, r, usersRedirect(false), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d/edit", id), http.StatusSeeOther)
}
