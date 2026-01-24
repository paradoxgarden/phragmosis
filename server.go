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
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

func verifyRedirect(redir string, domain string) (bool, error) {
	if !strings.HasPrefix("https://", redir) && !strings.HasPrefix(redir, "/") {
		redirect, err := url.JoinPath("https://", redir)
		if err != nil {
			return false, err
		}
		redir = redirect
	}
	redirect, err := url.Parse(redir)
	if err != nil {
		return false, err
	}
	goodDom := false
	if redirect.Host == domain {
		goodDom = true
	}
	if strings.HasPrefix(redir, "/") {
		goodDom = true
	}
	if strings.HasSuffix(redirect.Hostname(), "."+domain) {
		goodDom = true
	}
	if strings.HasPrefix(redir, "//") {
		return false, err
	}
	if !goodDom {
		return false, err
	}
	return true, nil
}
func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	redir := r.FormValue("redirect")
	isRedirectGood, err := verifyRedirect(redir, *s.cfg.DomainName)
	if !isRedirectGood {
		return
	}
	ometa, err := genOAuthMeta(redir)
	if err != nil {
		return
	}
	enc, err := s.sc.Encode("oauthMeta", *ometa)
	if err != nil {
		s.fail(w, r, "error encoding oauth metadata", err, slog.LevelError)
		return
	}
	s.writeCookie(w, "oauthMeta", enc, 300)

	discordURL := s.discordOauthcfg.AuthCodeURL(ometa.CRSFState, oauth2.S256ChallengeOption(ometa.PKCECode))
	err = s.loginTemplate.Execute(w, map[string]interface{}{
		"DiscordRedirect": discordURL,
		"DiscordVisible":  s.discord,
		"ATProtoVisible":  s.atproto,
	})
	if err != nil {
		s.fail(w, r, "login page rendering failed", err, slog.LevelError)
		return
	}
}
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

func (s *server) authHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")

	if err == http.ErrNoCookie {
		s.fail(w, r, "login page being sent to someone with no cookie", err, slog.LevelDebug)
		return
	}
	auth := &oauth2.Token{}
	err = s.sc.Decode("token", cookie.Value, &auth)
	if err != nil {
		s.writeCookie(w, "token", "", -1)
		s.fail(w, r, "token failed to decode", err, slog.LevelWarn)
		return
	}
	if !auth.Valid() {
		s.writeCookie(w, "token", "", -1)
		s.fail(w, r, "token did not pass validation", err, slog.LevelError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
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
func (s *server) atprotoHandler(w http.ResponseWriter, r *http.Request) {

}

func (s *server) errorHandler(w http.ResponseWriter, r *http.Request) {

	// TODO make error page nice
	s.errorTemplate.Execute(w, map[string]interface{}{
		"rzn": r.FormValue("rzn"),
	})
}
func (s *server) discordHandler(w http.ResponseWriter, r *http.Request) {
	ometa, err := getUserMeta(r, s.sc)
	if err != nil {
		s.fail(w, r, "user metadata validation failed", err, slog.LevelError)
	}
	code := r.FormValue("code")
	token, err := getDiscordToken(r.Context(), s.discordOauthcfg, code, ometa.PKCECode)
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
	token.SetAuthHeader(req)
	guildsResp, err := s.cl.Do(req)
	if err != nil {
		s.fail(w, r, "discord api error", err, slog.LevelError)
		return
	}
	var guilds []struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(guildsResp.Body).Decode(&guilds)
	if err != nil {
		s.fail(w, r, "discord api error", err, slog.LevelError)
		return
	}
	enc, err := s.sc.Encode("token", token)
	if err != nil {
		s.fail(w, r, "error encoding token", err, slog.LevelError)
		return
	}
	for _, g := range guilds {
		if *s.cfg.DiscordGuildID == g.ID {
			s.writeCookie(w, "token", enc, int(time.Hour) * 24 * 7)
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
	discordOauthcfg  oauth2.Config
	discordEndpoints oauth2.Endpoint
	discord          bool
	atproto          bool
	cl               http.Client
}

//go:embed static/*
var static embed.FS

//go:embed templates/*
var templates embed.FS

func initServ(c config, cookie securecookie.SecureCookie, client http.Client, loginTemplate template.Template, errorTemplate template.Template) *server {

	s := &server{
		cfg:           c,
		cl:            client,
		sc:            cookie,
		loginTemplate: loginTemplate,
		errorTemplate: errorTemplate,
	}
	if c.DiscordGuildID != nil && c.DiscordClientID != nil && c.DiscordClientSecret != nil {
		s.discord = true
	} else {
		s.discord = false
	}
	if c.DidAllowList != nil {
		s.atproto = true
	} else {
		s.atproto = false
	}
	if s.discord {
		s.discordEndpoints = oauth2.Endpoint{
			AuthURL:  "https://discord.com/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		}
		s.discordOauthcfg = oauth2.Config{
			ClientID:     *c.DiscordClientID,
			ClientSecret: *c.DiscordClientSecret,
			Scopes:       []string{"identify", "guilds"},
			Endpoint:     s.discordEndpoints,
		}
	}
	if c.Subdomain != nil {
		s.selfDomain = fmt.Sprintf("%s.%s", *c.Subdomain, *c.DomainName)
	} else {
		s.selfDomain = *c.DomainName
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
	s := initServ(*c, *cookie, *cl, *loginTemplate, *errorTemplate)
	http.HandleFunc("/", s.loginHandler)
	http.HandleFunc("/auth", s.authHandler)
	http.HandleFunc("/callback/discord", s.discordHandler)
	http.HandleFunc("/callback/@proto", s.atprotoHandler)
	http.HandleFunc("/error", s.errorHandler)
	content, err := fs.Sub(static, "static")
	if err != nil {
		log.Fatal("could not load static files")
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(content))))
	slog.Info("listening on port: " + *s.cfg.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", *s.cfg.Port), nil))
}
