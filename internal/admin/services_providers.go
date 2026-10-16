package admin

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const maxProviderPosition = 9999

// HandleServiceUpdate erstatter tjenestens leverandørtilordninger. Skjemaet har
// provider_<id>=on og position_<id>=<int>. Bare leverandører som er lastet i
// registeret godtas: en id utenfor settet gir 400 uten noen endring, slik at
// en tilordning aldri peker på noe innloggingen ikke kan bruke.
func (h *ProvidersHandler) HandleServiceUpdate(w http.ResponseWriter, r *http.Request) {
	serviceID := chi.URLParam(r, "id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ugyldig skjema", http.StatusBadRequest)
		return
	}

	// Uavhengig av active-flagget: admin må kunne tilordne for deaktiverte tjenester.
	svc, err := findServiceByID(r.Context(), h.queries, serviceID)
	if err == nil && svc == nil {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("admin: oppslag av tjeneste feilet", "service_id", serviceID, "error", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	loaded := map[int64]string{} // id -> slug
	for _, s := range h.idps.Statuses() {
		if s.Loaded {
			loaded[s.ID] = s.Slug
		}
	}

	type pick struct {
		id   int64
		slug string
		pos  int64
	}
	var picks []pick
	for key, vals := range r.PostForm {
		idStr, ok := strings.CutPrefix(key, "provider_")
		if !ok || len(vals) == 0 || vals[len(vals)-1] != "on" {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		slug, isLoaded := loaded[id]
		if err != nil || !isLoaded {
			http.Error(w, "ukjent eller ikke lastet leverandør", http.StatusBadRequest)
			return
		}
		pos := int64(0)
		if raw := strings.TrimSpace(r.PostFormValue(idKey("position_", id))); raw != "" {
			pos, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || pos < 0 || pos > maxProviderPosition {
				http.Error(w, "ugyldig posisjon", http.StatusBadRequest)
				return
			}
		}
		picks = append(picks, pick{id: id, slug: slug, pos: pos})
	}
	sort.Slice(picks, func(i, j int) bool {
		if picks[i].pos != picks[j].pos {
			return picks[i].pos < picks[j].pos
		}
		return picks[i].slug < picks[j].slug
	})

	current, err := h.queries.ListAssignmentsForService(r.Context(), serviceID)
	if err != nil {
		slog.Error("admin: les tilordninger feilet", "service_id", serviceID, "error", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	// remove_<id> gjelder bare tilordninger som står der i dag til en leverandør som ikke er
	// lastet; lastede fjernes ved å fjerne avkrysningen.
	removeIDs := map[int64]bool{}
	for key, vals := range r.PostForm {
		idStr, ok := strings.CutPrefix(key, "remove_")
		if !ok || len(vals) == 0 || vals[len(vals)-1] != "on" {
			continue
		}
		id, perr := strconv.ParseInt(idStr, 10, 64)
		valid := false
		if perr == nil {
			_, isLoaded := loaded[id]
			for _, c := range current {
				if c.ProviderID == id && !isLoaded {
					valid = true
				}
			}
		}
		if !valid {
			http.Error(w, "kan ikke fjerne denne leverandøren", http.StatusBadRequest)
			return
		}
		removeIDs[id] = true
	}

	// WithoutCancel: en klient som kobler fra midt i skrivingen skal ikke
	// etterlate en halv tilordning.
	ctx := context.WithoutCancel(r.Context())
	var kept, removed []string
	err = token.RunInTx(ctx, h.sqlDB, func(q *gen.Queries) error {
		// Tilordninger til leverandører som ikke er lastet vises ikke i skjemaet og
		// beholdes, så de ikke forsvinner stille; de får virkning først etter omstart.
		existing, err := q.ListAssignmentsForService(ctx, serviceID)
		if err != nil {
			return err
		}
		if err := q.DeleteServiceIdentityProviders(ctx, serviceID); err != nil {
			return err
		}
		kept, removed = nil, nil
		for _, e := range existing {
			if _, isLoaded := loaded[e.ProviderID]; isLoaded {
				continue
			}
			if removeIDs[e.ProviderID] {
				removed = append(removed, e.Slug)
				continue
			}
			kept = append(kept, fmt.Sprintf("%s:%d", e.Slug, e.Position))
			if err := q.InsertServiceIdentityProvider(ctx, gen.InsertServiceIdentityProviderParams{
				ServiceID: serviceID, ProviderID: e.ProviderID, Position: e.Position,
			}); err != nil {
				return err
			}
		}
		for _, p := range picks {
			if err := q.InsertServiceIdentityProvider(ctx, gen.InsertServiceIdentityProviderParams{
				ServiceID: serviceID, ProviderID: p.id, Position: p.pos,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		slog.Error("admin: lagring av leverandørtilordning feilet", "service_id", serviceID, "error", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	parts := make([]string, 0, len(picks))
	for _, p := range picks {
		parts = append(parts, fmt.Sprintf("%s:%d", p.slug, p.pos))
	}
	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:      "service_providers_updated",
		ServiceID: serviceID,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Success:   true,
		Details: fmt.Sprintf("service=%s providers=%s kept=%s removed=%s",
			serviceID, strings.Join(parts, ","), strings.Join(kept, ","), strings.Join(removed, ",")),
	})

	// Lagringen står uansett; en feilet omlasting betyr at innloggingen fortsatt
	// bruker forrige tilordning til neste omstart, og det må admin få vite.
	reloadOK := true
	if err := h.idps.ReloadAssignments(ctx, h.queries); err != nil {
		slog.Error("admin: omlasting av leverandørtilordning feilet etter lagring", "service_id", serviceID, "error", err)
		reloadOK = false
	}

	var warns []string
	if !reloadOK {
		warns = append(warns, "reload")
	}
	if !auditOK {
		warns = append(warns, "audit")
	}
	http.Redirect(w, r, redirectWithWarns("/admin/services/"+serviceID+"/edit", warns...), http.StatusSeeOther)
}
