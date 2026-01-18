package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var atproto_redirect_string = "https://?"

func getRandBytes(n int) []byte {
	dat := make([]byte, n)
	_, err := rand.Read(dat)
	if err != nil {
		log.Fatal("randomness as we know it has ceased")
	}
	return dat
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	verf := oauth2.GenerateVerifier()
	state := base64.URLEncoding.EncodeToString(getRandBytes(16))
	redir := r.URL.Query().Get("redirect")
	redirect, err := url.Parse("https://" + redir)
	if err != nil {
		s.redirectLogin(w, r)
		return
	}
	goodDom := false
	for _, dom := range s.config.AllowedDomains {
		if redirect.Host == dom || strings.HasSuffix(redirect.Hostname(), "."+dom) {
			goodDom = true
		}
	}
	if !goodDom && !strings.HasPrefix(redir, "/") || strings.HasPrefix(redir, "//") {
		s.redirectLogin(w, r)
		return
	}
	enc, err := s.sc.Encode("oauth_meta", map[string]string{
		"state":    state,
		"verf":     verf,
		"redirect": redirect.String(),
	})
	if err != nil {
		s.redirectLogin(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_meta",
		Value:    enc,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	discordURL := s.discordOauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verf))
	s.loginPageTemplate.Execute(w, map[string]string{
		"DiscordRedirect": discordURL,
		"ATProtoRedirect": "",
	})
}

func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	originalDest := host + uri
	http.Redirect(w, r, fmt.Sprintf("https://%s?redirect=%s", s.selfDomain, originalDest), http.StatusFound)
}

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")

	if err == http.ErrNoCookie {
		s.redirectLogin(w, r)
		return
	}
	var auth map[string]interface{}
	err = s.sc.Decode("token", cookie.Value, &auth)
	if err != nil {
		s.redirectLogin(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("provider")
	switch from {
	case "discord":
		cookie, err := r.Cookie("oauth_meta")
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		var oauth_meta map[string]string
		s.sc.Decode("oauth_meta", cookie.Value, &oauth_meta)
		if oauth_meta["state"] != r.URL.Query().Get("state") {
			s.redirectLogin(w, r)
			return
		}
		payload := url.Values{}
		payload.Set("grant_type", "authorization_code")
		codes := r.URL.Query()["code"]
		if len(codes) == 0 {
			s.redirectLogin(w, r)
			return
		}
		payload.Set("code", codes[0])
		payload.Set("code_verifier", oauth_meta["verf"])

		req, err := http.NewRequest("POST", s.discordEndpoints.TokenURL, strings.NewReader(payload.Encode()))
		if err != nil {
			s.redirectLogin(w, r)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(*s.config.DiscordClientID, *s.config.DiscordClientSecret)
		cl := &http.Client{Timeout: 10 * time.Second}
		resp, err := cl.Do(req)
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		defer resp.Body.Close()
		var res map[string]interface{}

		err = json.NewDecoder(resp.Body).Decode(&res)
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		req, err = http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", res["access_token"]))
		guildsResp, err := cl.Do(req)
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		var guilds []struct {
			ID string `json:"id"`
		}
		err = json.NewDecoder(guildsResp.Body).Decode(&guilds)
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		enc, err := s.sc.Encode("token", res)
		if err != nil {
			s.redirectLogin(w, r)
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
				http.Redirect(w, r, oauth_meta["redirect"], http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return

	default:
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

}

type Server struct {
	sc                 securecookie.SecureCookie
	discordOauthConfig oauth2.Config
	selfDomain         string
	config             Config
	loginPageTemplate  template.Template
	discordEndpoints   oauth2.Endpoint
}

func main() {
	var server Server
	config := loadConfig()
	fmt.Println(config)
	server.discordEndpoints = oauth2.Endpoint{
		AuthURL:  "https://discord.com/oauth2/authorize",
		TokenURL: "https://discord.com/api/oauth2/token",
	}
	server.loginPageTemplate = *template.Must(template.ParseFiles("./static/login.html"))
	if config.Subdomain != nil {
		server.selfDomain = fmt.Sprintf("%s.%s/", *config.Subdomain, *config.DomainName)
	} else {
		server.selfDomain = fmt.Sprintf("%s/", *config.DomainName)
	}
	server.discordOauthConfig = oauth2.Config{
		ClientID:     *config.DiscordClientID,
		ClientSecret: *config.DiscordClientSecret,
		Scopes:       []string{"identify", "guilds"},
		Endpoint:     server.discordEndpoints,
	}
	if config.BlockKey == nil || config.HashKey == nil {
		server.sc = *securecookie.New(getRandBytes(32), getRandBytes(32))
	} else {
		hashKey, err := base64.StdEncoding.DecodeString(*config.HashKey)
		if err != nil {
			log.Fatal("provided hash key is not b64 encoded")
		}
		blockKey, err := base64.StdEncoding.DecodeString(*config.BlockKey)
		if err != nil {
			log.Fatal("provided hash key is not b64 encoded")
		}
		server.sc = *securecookie.New(hashKey, blockKey)
	}

	server.config = config
	http.HandleFunc("/", server.loginHandler)
	http.HandleFunc("/auth", server.authHandler)
	http.HandleFunc("/callback/{provider}", server.callbackHandler)
	fmt.Println("listening on port:", *config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", *config.Port), nil))
}
