package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

// ensure user redirect isn't malicious or malformed
func verifyRedirect(redir string, domain string) (string, error) {

	if redir == "/" {
		return "https://" + domain + "/", nil
	}
	if !strings.HasPrefix(redir, "http://") && !strings.HasPrefix(redir, "https://") {
		redir = "https://" + redir
	}
	u, err := url.Parse(redir)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URL: %w", err)
	}
	hostname := u.Hostname()
	if hostname != domain && !strings.HasSuffix(hostname, "."+domain) {
		return "", fmt.Errorf("redirect domain %s not allowed (expected %s or subdomain)", hostname, domain)
	}

	return u.String(), nil
}

// render & serve the login page
func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	redir := r.FormValue("redirect")
	goodRedirect, err := verifyRedirect(redir, *s.cfg.DomainName)
	if err != nil {
		s.fail(w, r, "error verifying redirect", err, slog.LevelError)
	}
	ometa, err := genOAuthMeta(goodRedirect)
	if err != nil {
		s.fail(w, r, "error generating oauth metadata", err, slog.LevelError)
	}
	enc, err := s.sc.Encode("oauthMeta", *ometa)
	if err != nil {
		s.fail(w, r, "error encoding oauth metadata", err, slog.LevelError)
		return
	}
	s.writeCookie(w, "oauthMeta", enc, 300)

	discordURL := s.discordOAuth.AuthCodeURL(ometa.CRSFState, oauth2.S256ChallengeOption(ometa.PKCECode))
	err = s.loginTemplate.Execute(w, map[string]interface{}{
		"DiscordRedirect": discordURL,
		"DiscordVisible":  s.discord,
		"ATProtoVisible":  s.atproto,
		"PageTitle":       s.cfg.PageTitle,
	})
	if err != nil {
		s.fail(w, r, "login page rendering failed", err, slog.LevelError)
		return
	}
}

// an error has occured, force the user to restart the process
func (s *server) fail(w http.ResponseWriter, r *http.Request, rzn string, err error, level slog.Level) {
	if err != nil {
		slog.Log(r.Context(), level, rzn, "error", err, "path", r.URL.Path)
	} else {
		slog.Log(r.Context(), level, rzn, "path", r.URL.Path)
	}
	redir := "/"
	err = s.redirect(w, r, redir)
	if err != nil {
		slog.Log(r.Context(), slog.LevelError, "bad internal redirect", "error", err, "path", r.URL.Path)
		s.redirect(w, r, "/error?rzn=bad internal redirect")
	}
}

// send the user to their intended destination (happy path)
func (s *server) redirect(w http.ResponseWriter, r *http.Request, path string) error {
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	originalDest, err := url.JoinPath(host, uri, path)
	if err != nil {
		return err
	}
	if strings.Contains(path, "?") {
		http.Redirect(w, r, fmt.Sprintf("https://%s/&redirect=%s", s.selfDomain, originalDest), http.StatusFound)
	} else {
		http.Redirect(w, r, fmt.Sprintf("https://%s/?redirect=%s", s.selfDomain, originalDest), http.StatusFound)
	}
	return nil
}

// forward auth route
// if this fails, the user is sent to the login page
func (s *server) authHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")

	if err == http.ErrNoCookie {
		s.fail(w, r, "login page being sent to someone with no cookie", err, slog.LevelDebug)
		return
	}
	tok := &token{}
	err = s.sc.Decode("token", cookie.Value, tok)
	if err != nil {
		s.writeCookie(w, "token", "", -1)
		s.fail(w, r, "token failed to decode", err, slog.LevelWarn)
		return
	}
	if !tok.Valid() {
		s.writeCookie(w, "token", "", -1)
		s.fail(w, r, "token did not pass validation", err, slog.LevelError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// write a cookie to the users browser session
func (s *server) writeCookie(w http.ResponseWriter, name string, value string, maxAge int) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Domain:   *s.cfg.DomainName,
		MaxAge:   maxAge,
	}
	err := c.Valid()
	if err != nil {
		slog.Log(nil, slog.LevelError, "Problem writing cookie:", err)
	}

	http.SetCookie(w, c)
}

var name = "phragmosis"

// serve client metadata document for oauth
func (s *server) handleClientMetadata(w http.ResponseWriter, r *http.Request) {
	doc := s.atprotoOAuth.Config.ClientMetadata()
	doc.ClientName = &name
	// if this is is a confidential client, need to set doc.JWKSURI, and implement a handler

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// backend route to resolve did & begin atproto oauth flow
func (s *server) handleResolveDid(w http.ResponseWriter, r *http.Request) {
	var ctx = r.Context()
	hand, err := syntax.ParseHandle(r.FormValue("handle"))
	if err != nil {
		slog.Log(r.Context(), slog.LevelError, "unable to parse handle:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ident, err := s.didCache.LookupHandle(r.Context(), hand)
	if err != nil {
		slog.Log(ctx, slog.LevelError, "unable to resolve ident: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redir, err := s.atprotoOAuth.StartAuthFlow(r.Context(), ident.DID.String())
	if err != nil {
		slog.Log(ctx, slog.LevelError, "unable to start auth flow (bad pds?):", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]string{"redirect": redir}); err != nil {
		slog.Log(ctx, slog.LevelError, "", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

// atproto callback
func (s *server) atprotoHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ses, err := s.atprotoOAuth.ProcessCallback(r.Context(), r.Form)
	if err != nil {
		return
	}
	ometa, err := getUserMeta(r, s.sc)
	if err != nil {
		s.fail(w, r, "user metadata validation failed", err, slog.LevelError)
	}
	tok := token{
		Access:  ses.AccessToken,
		Refresh: ses.RefreshToken,
		Subject: (*string)(&ses.AccountDID),
		Iat:     time.Now().String(),
	}
	enc, err := s.sc.Encode("token", tok)
	if err != nil {
		s.fail(w, r, "error encoding token", err, slog.LevelError)
		return
	}

	if slices.Contains(s.cfg.DidAllowList, ses.AccountDID.String()) {
		s.writeCookie(w, "token", enc, int(time.Hour)*24*7)
		slog.Log(r.Context(), slog.LevelInfo, "successful flow, user has logged in correctly")
		http.Redirect(w, r, "https://"+ometa.Redirect, http.StatusFound)
		return
	}

}

// render the error page (wip)
func (s *server) errorHandler(w http.ResponseWriter, r *http.Request) {

	// TODO make error page nice
	s.errorTemplate.Execute(w, map[string]interface{}{
		"rzn":       r.FormValue("rzn"),
		"PageTitle": s.cfg.PageTitle,
	})
}

// discord callback
func (s *server) discordHandler(w http.ResponseWriter, r *http.Request) {
	ometa, err := getUserMeta(r, s.sc)
	if err != nil {
		s.fail(w, r, "user metadata validation failed", err, slog.LevelError)
	}
	code := r.FormValue("code")
	discordTok, err := getDiscordToken(r.Context(), s.discordOAuth, code, ometa.PKCECode)
	if err != nil {
		s.fail(w, r, "token did not pass validation", err, slog.LevelError)
		s.writeCookie(w, "token", "", 604800)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), "GET", "https://discord.com/api/users/@me/guilds", nil)
	if err != nil {
		s.fail(w, r, "creation of http request from static resources FAILED somehow", err, slog.LevelError)
		return
	}
	discordTok.SetAuthHeader(req)
	guildsResp, err := s.cl.Do(req)
	if err != nil {
		s.fail(w, r, "discord api error", err, slog.LevelError)
		return
	}
	subject := "token"
	tok := token{
		Access:  discordTok.AccessToken,
		Refresh: discordTok.RefreshToken,
		Subject: &subject,
		Iat:     time.Now().String(),
	}

	enc, err := s.sc.Encode("token", tok)
	if err != nil {
		s.fail(w, r, "error encoding token", err, slog.LevelError)
		return
	}
	var guilds []struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(guildsResp.Body).Decode(&guilds)
	defer guildsResp.Body.Close()
	if err != nil {
		s.fail(w, r, "discord api error", err, slog.LevelError)
		return
	}
	for _, g := range guilds {
		if *s.cfg.DiscordGuildID == g.ID {
			s.writeCookie(w, "token", enc, int(time.Hour)*24*7)
			slog.Log(r.Context(), slog.LevelInfo, "successful flow, user has logged in correctly")
			http.Redirect(w, r, "https://"+ometa.Redirect, http.StatusFound)
			return
		}
	}
	s.fail(w, r, "user not in circle of trust", err, slog.LevelWarn)
}

type server struct {
	cfg              config
	sc               securecookie.SecureCookie
	selfDomain       string
	loginTemplate    template.Template
	errorTemplate    template.Template
	discordOAuth     oauth2.Config
	discordEndpoints oauth2.Endpoint
	discord          bool
	cl               http.Client
	atproto          bool
	atprotoOAuth     *oauth.ClientApp
	didCache         *identity.CacheDirectory
}

//go:embed static/*
var static embed.FS

//go:embed templates/*
var templates embed.FS

const SEVEN_DAYS = time.Hour * 24 * 7

// correctly instantiate a new server from config
func newServer(c config, cookie securecookie.SecureCookie, client http.Client, loginTemplate template.Template, errorTemplate template.Template) *server {

	s := &server{
		cfg:           c,
		cl:            client,
		sc:            cookie,
		loginTemplate: loginTemplate,
		errorTemplate: errorTemplate,
	}
	if c.Subdomain != nil {
		s.selfDomain = fmt.Sprintf("%s.%s", *c.Subdomain, *c.DomainName)
	} else {
		s.selfDomain = *c.DomainName
	}
	if c.DiscordGuildID != nil && c.DiscordClientID != nil && c.DiscordClientSecret != nil {
		s.discord = true
	} else {
		s.discord = false
	}
	if c.DidAllowList != nil {
		s.atproto = true
		// cache limit set to 10k max default, might not matter to uncap?
		cd := identity.NewCacheDirectory(&identity.BaseDirectory{}, 10000, SEVEN_DAYS, SEVEN_DAYS, SEVEN_DAYS)
		s.didCache = &cd
		config := oauth.NewPublicConfig(
			fmt.Sprintf("https://%s/client-metadata.json", s.selfDomain),
			fmt.Sprintf("https://%s/callback/@proto", s.selfDomain),
			[]string{"atproto"},
		)

		//	if CLIENT_SECRET_KEY != "" {
		//		priv, err := crypto.ParsePrivateMultibase(CLIENT_SECRET_KEY)
		//		if err != nil {
		//			return err
		//		}
		//		if err := config.SetClientSecret(priv, "example1"); err != nil {
		//			return err
		//		}
		//	}

		s.atprotoOAuth = oauth.NewClientApp(&config, oauth.NewMemStore())

	} else {
		s.atproto = false
	}
	if s.discord {
		s.discordEndpoints = oauth2.Endpoint{
			AuthURL:  "https://discord.com/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		}
		s.discordOAuth = oauth2.Config{
			ClientID:     *c.DiscordClientID,
			ClientSecret: *c.DiscordClientSecret,
			Scopes:       []string{"identify", "guilds"},
			Endpoint:     s.discordEndpoints,
		}
	}
	s.cfg = c
	return s
}
func main() {
	c, err := loadConfig()
	if err != nil {
		log.Fatalf("bad cfg: %v", err)
	}
	logLevel := slog.LevelInfo
	if *c.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	cookie, err := initSecureCookie(c.BlockKey, c.HashKey)
	if err != nil {
		log.Fatal("creating securecookie failed: ", err)
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	loginTemplate, err := template.ParseFS(templates, "templates/login.html")
	if err != nil {
		log.Fatal("embedded html FAILED: ", err)
	}
	errorTemplate, err := template.ParseFS(templates, "templates/error.html")
	if err != nil {
		log.Fatal("embedded html FAILED: ", err)
	}
	s := newServer(*c, *cookie, *cl, *loginTemplate, *errorTemplate)
	http.HandleFunc("/", s.loginHandler)
	http.HandleFunc("/auth", s.authHandler)
	http.HandleFunc("/callback/discord", s.discordHandler)
	http.HandleFunc("/callback/@proto", s.atprotoHandler)
	http.HandleFunc("/client-metadata.json", s.handleClientMetadata)
	http.HandleFunc("/handleLogin", s.handleResolveDid)
	http.HandleFunc("/error", s.errorHandler)
	content, err := fs.Sub(static, "static")
	if err != nil {
		log.Fatal("could not load static files")
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(content))))
	slog.Info("listening on port: " + *s.cfg.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", *s.cfg.Port), nil))
}
