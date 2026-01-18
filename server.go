package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
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

func (s *server) loginHandler(w http.ResponseWriter, r *http.Request) {
	verf := oauth2.GenerateVerifier()
	stateRand, err := getRandBytes(16)
	if err != nil {
		s.fail(w, r, "randomness as we know it has ceased", err, slog.LevelError)

		return
	}
	state := base64.URLEncoding.EncodeToString(stateRand)
	redir := r.FormValue("redirect")
	redirect, err := url.Parse("https://" + redir)
	if err != nil {
		s.fail(w, r, "malformed redirect", err, slog.LevelWarn)
		return
	}
	goodDom := false
	for _, dom := range s.config.AllowedDomains {
		if redirect.Host == dom || strings.HasSuffix(redirect.Hostname(), "."+dom) {
			goodDom = true
		}
	}
	if (!goodDom && !strings.HasPrefix(redir, "/")) ||
		strings.HasPrefix(redir, "//") {
		s.fail(w, r, "malformed redirect", err, slog.LevelWarn)
		return
	}
	enc, err := s.sc.Encode("oauthMeta", map[string]string{
		"state":    state,
		"verf":     verf,
		"redirect": redirect.String(),
	})
	if err != nil {
		s.fail(w, r, "error encoding oauth metadata", err, slog.LevelError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauthMeta",
		Value:    enc,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	discordURL := s.discordOauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verf))
	err = s.loginPageTemplate.Execute(w, map[string]string{
		"DiscordRedirect": discordURL,
		"ATProtoRedirect": "",
		"rzn":             r.FormValue("rzn"),
	})
	if err != nil {
		s.fail(w, r, "login page rendering failed", err, slog.LevelError)
	}
}
func (s *server) fail(
	w http.ResponseWriter,
	r *http.Request,
	rzn string,
	err error,
	level slog.Level,
) {
	if err != nil {
		slog.Log(r.Context(), level, rzn, "error", err, "path", r.URL.Path)
	} else {
		slog.Log(r.Context(), level, rzn, "path", r.URL.Path)
	}

	s.redirectLogin(w, r)
}
func (s *server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	originalDest := host + uri
	http.Redirect(w, r, fmt.Sprintf("https://%s?redirect=%s", s.selfDomain, originalDest), http.StatusFound)
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
		s.fail(w, r, "token failed to decode", err, slog.LevelWarn)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("provider")
	switch from {
	case "discord":
		cookie, err := r.Cookie("oauthMeta")
		if err != nil {
			s.fail(w, r, "no cookie for callback", err, slog.LevelWarn)
			return
		}
		var oauthMeta map[string]string
		code := r.FormValue("code")
		state := r.FormValue("state")
		err = s.sc.Decode("oauthMeta", cookie.Value, &oauthMeta)
		if err != nil {
			s.fail(w, r, "cookie failed to decode", err, slog.LevelWarn)
			return
		}
		if oauthMeta["state"] != state {
			s.fail(w, r, "state validation failed for CRSF protection", err, slog.LevelWarn)
			return
		}
		token, err := s.discordOauthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(oauthMeta["verf"]))
		if err != nil {
			s.fail(w, r, "discord token exchange failed", err, slog.LevelError)
			return
		}
		req, err := http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
		if err != nil {
			s.fail(w, r, "creation of http request from static resources FAILED somehow", err, slog.LevelError)
			return
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
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
			if *s.config.DiscordGuildID == g.ID {
				http.SetCookie(w, &http.Cookie{
					Name:     "token",
					Value:    enc,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
					Domain:   *s.config.DomainName,
					MaxAge:   604800,
				})
				http.Redirect(w, r, oauthMeta["redirect"], http.StatusFound)
				return
			}
		}
		s.fail(w, r, "user not in circle of trust", err, slog.LevelWarn)
		return

	default:
		s.fail(w, r, "bad callback", nil, slog.LevelWarn)
		return
	}

}

type server struct {
	config             config
	sc                 securecookie.SecureCookie
	selfDomain         string
	loginPageTemplate  template.Template
	discordOauthConfig oauth2.Config
	discordEndpoints   oauth2.Endpoint
	discord            bool
	atproto            bool
	cl                 http.Client
}

//go:embed static/*
var static embed.FS

func initServ(c config) *server {

	s := &server{}
	if c.DiscordGuildID != nil || c.DiscordClientID != nil || c.DiscordClientSecret != nil {
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
		s.discordOauthConfig = oauth2.Config{
			ClientID:     *c.DiscordClientID,
			ClientSecret: *c.DiscordClientSecret,
			Scopes:       []string{"identify", "guilds"},
			Endpoint:     s.discordEndpoints,
		}
	}
	temp, err := template.ParseFS(static, "static/login.html")
	if err != nil {
		log.Fatal("embedded html FAILED: ", err)
	}
	s.loginPageTemplate = *temp
	if c.Subdomain != nil {
		s.selfDomain = fmt.Sprintf("%s.%s/", *c.Subdomain, *c.DomainName)
	} else {
		s.selfDomain = fmt.Sprintf("%s/", *c.DomainName)
	}
	s.cl = http.Client{Timeout: time.Second * 10}
	cookie, err := initSecureCookie(c.BlockKey, c.HashKey)
	if err != nil {
		log.Fatal("creating securecookie failed: ", err)
	}
	s.sc = cookie
	s.config = c
	return s
}
func main() {
	c, err := loadConfig()
	if err != nil {
		log.Fatalf("bad config: %v", err)
	}
	logLevel := slog.LevelInfo
	if *c.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	s := initServ(*c)
	http.HandleFunc("/", s.loginHandler)
	http.HandleFunc("/auth", s.authHandler)
	http.HandleFunc("/callback/{provider}", s.callbackHandler)
	slog.Info("listening on port: " + *s.config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", *s.config.Port), nil))
}
