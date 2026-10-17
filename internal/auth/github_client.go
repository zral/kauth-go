package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Sentinel-feil fra GitHub-klienten. Kalleren mapper dem til faste reasons i
// audit. Ingen av dem bærer tekst fra GitHub, så de kan aldri nå brukeren.
var (
	errGHCodeExchange = errors.New("github: kodeutveksling feilet")
	errGHUserFetch    = errors.New("github: brukeroppslag feilet")
	errGHMissingID    = errors.New("github: mangler gyldig bruker-id")
)

// githubNoreplyDomain er roten for GitHubs skjulte adresser
// (users.noreply.github.com m.fl.). De bærer ingen reell kontroll over en
// postkasse og er ikke et grunnlag for å koble kontoer.
const githubNoreplyDomain = "noreply.github.com"

// githubClient snakker med GitHubs OAuth- og REST-endepunkter. http kommer fra
// idp.NewHTTPClient: SSRF-vakt, ingen redirects, tidsavbrudd og 1 MiB tak på
// svar, som feiler høyt i stedet for å avkorte.
type githubClient struct {
	http    *http.Client
	baseURL string
	apiURL  string
}

// ghUser er feltene fra GET /user som kauth bruker. ID holdes som rå tallekst
// slik at 1.0, 1e3 og strenger kan avvises i stedet for å bli rundet av
// float64.
type ghUser struct {
	ID   json.Number
	Name string
}

// ghEmail er én oppføring fra GET /user/emails.
type ghEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// subject gir GitHub-id-en som stabil subject. Bare ren heltallstekst > 0
// godtas: ParseInt avviser 1.0, 1e3 og tom verdi, og den kanoniske
// tilbakeformatteringen avviser f.eks. «+5» og ledende nuller.
func (u ghUser) subject() (string, error) {
	txt := u.ID.String()
	id, err := strconv.ParseInt(txt, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != txt {
		return "", errGHMissingID
	}
	return txt, nil
}

// exchange bytter autorisasjonskoden mot et access-token. GitHub svarer 200
// også ved feil, med «error» i JSON-en, så status alene er ikke nok.
func (c *githubClient) exchange(ctx context.Context, clientID, secret, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errGHCodeExchange
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kauth")
	resp, err := c.http.Do(req)
	if err != nil {
		// Feilen nevner bare metode og URL. Koden og hemmeligheten ligger i
		// skjemaet, så den kan logges og skille tidsavbrudd fra DNS- og TLS-feil.
		slog.Warn("github: kodeutveksling feilet", "reason", "transport", "error", err)
		return "", errGHCodeExchange
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("github: kodeutveksling feilet", "reason", "status", "status", resp.StatusCode)
		return "", errGHCodeExchange
	}
	var out struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		slog.Warn("github: kodeutveksling feilet", "reason", "bad_json")
		return "", errGHCodeExchange
	}
	if out.Error != "" {
		slog.Warn("github: kodeutveksling avvist",
			"error", sanitizeLogValue(truncate(out.Error, 64)),
			"description", sanitizeLogValue(truncate(out.ErrorDescription, 200)))
		return "", errGHCodeExchange
	}
	if out.AccessToken == "" || !strings.EqualFold(out.TokenType, "bearer") {
		slog.Warn("github: kodeutveksling feilet", "reason", "bad_token_response")
		return "", errGHCodeExchange
	}
	return out.AccessToken, nil
}

// user henter GET /user. Manglende eller ugyldig id gir errGHMissingID, og
// ingen annen del av svaret brukes til å avgjøre hvem brukeren er.
func (c *githubClient) user(ctx context.Context, accessToken string) (ghUser, error) {
	var raw struct {
		ID   json.RawMessage `json:"id"`
		Name *string         `json:"name"`
	}
	if err := c.getJSON(ctx, "/user", accessToken, &raw); err != nil {
		return ghUser{}, err
	}
	u := ghUser{}
	if n := string(raw.ID); n != "" && (n[0] == '-' || (n[0] >= '0' && n[0] <= '9')) {
		// Bare et JSON-tall; en streng («"123"») eller null gir tom ID.
		u.ID = json.Number(n)
	}
	if raw.Name != nil {
		u.Name = *raw.Name
	}
	if _, err := u.subject(); err != nil {
		return ghUser{}, err
	}
	return u, nil
}

// emails henter GET /user/emails (krever scope user:email).
func (c *githubClient) emails(ctx context.Context, accessToken string) ([]ghEmail, error) {
	var out []ghEmail
	if err := c.getJSON(ctx, "/user/emails", accessToken, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *githubClient) getJSON(ctx context.Context, path, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+path, nil)
	if err != nil {
		return errGHUserFetch
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "kauth")
	resp, err := c.http.Do(req)
	if err != nil {
		// Tokenet ligger i en header, ikke i URL-en feilen nevner.
		slog.Warn("github: API-kall feilet", "path", path, "reason", "transport", "error", err)
		return errGHUserFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("github: API-kall feilet", "path", path, "status", resp.StatusCode)
		return errGHUserFetch
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		slog.Warn("github: API-kall feilet", "path", path, "reason", "bad_json")
		return errGHUserFetch
	}
	return nil
}

// pickEmail velger primæradressen og sier om den kan brukes som tillitsgrunnlag.
// Bare primær adresse vurderes; to primære er et brudd på GitHubs kontrakt og
// regnes som ikke betrodd. Adressen trimmes ikke: rawEmailSafe avviser
// mellomrom og ikke-ASCII, slik at en forfalsket adresse aldri normaliseres
// til en annen brukers. Ikke betrodd gir tom e-post, ikke en uverifisert en.
func pickEmail(list []ghEmail) (email string, trusted bool) {
	var primary *ghEmail
	for i := range list {
		if !list[i].Primary {
			continue
		}
		if primary != nil {
			return "", false
		}
		primary = &list[i]
	}
	if primary == nil || !primary.Verified || !rawEmailSafe(primary.Email) {
		return "", false
	}
	at := strings.LastIndexByte(primary.Email, '@')
	if domain := strings.ToLower(primary.Email[at+1:]); domain == githubNoreplyDomain || strings.HasSuffix(domain, "."+githubNoreplyDomain) {
		return "", false
	}
	return primary.Email, true
}
