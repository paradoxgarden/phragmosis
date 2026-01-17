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

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

var atproto_redirect_string = "https://?"

func getRandBytes(n int) []byte {
	dat := make([]byte, n)
	rand.Read(dat)
	return dat
}

var discordEndpoints = oauth2.Endpoint{
	AuthURL:  "https://discord.com/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

var loginPageTemplate = template.Must(template.ParseFiles("./static/login.html"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	verf := oauth2.GenerateVerifier()
	state := base64.URLEncoding.EncodeToString(getRandBytes(16))
	redirect, _ := url.Parse(r.URL.Query().Get("redirect"))
	if strings.HasPrefix(redirect.String(), "http:") || strings.HasPrefix(redirect.String(), "/") {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	enc, _ := sc.Encode("oauth_meta", map[string]string{
		"state":    state,
		"verf":     verf,
		"redirect": redirect.String(),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_meta",
		Value:    enc,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	discordURL := discordOauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verf))
	loginPageTemplate.Execute(w, map[string]string{
		"DiscordRedirect": discordURL,
		"ATProtoRedirect": "",
	})
}

func redirectLogin(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	originalDest := "https://" + host + uri
	http.Redirect(w, r, fmt.Sprintf("%s?redirect=%s", selfDomain, originalDest), http.StatusFound)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")

	if err == http.ErrNoCookie {
		redirectLogin(w, r)
		return
	}
	var auth map[string]interface{}
	err = sc.Decode("token", cookie.Value, &auth)
	if err != nil {
		redirectLogin(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	config := loadConfig()
	from := r.PathValue("provider")
	switch from {
	case "discord":
		cookie, _ := r.Cookie("oauth_meta")
		var oauth_meta map[string]string
		sc.Decode("oauth_meta", cookie.Value, &oauth_meta)
		if oauth_meta["state"] != r.URL.Query().Get("state") {
			return
		}
		payload := url.Values{}
		payload.Set("grant_type", "authorization_code")
		payload.Set("code", r.URL.Query()["code"][0])
		payload.Set("code_verifier", oauth_meta["verf"])

		req, err := http.NewRequest("POST", discordEndpoints.TokenURL, strings.NewReader(payload.Encode()))
		if err != nil {
			redirectLogin(w, r)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(*config.DiscordClientID, *config.DiscordClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			redirectLogin(w, r)
		}
		defer resp.Body.Close()
		var res map[string]interface{}

		json.NewDecoder(resp.Body).Decode(&res)
		req, err = http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
		if err != nil {
			redirectLogin(w, r)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", res["access_token"]))
		guildsResp, err := http.DefaultClient.Do(req)
		if err != nil {
			redirectLogin(w, r)
		}
		var guilds []struct {
			ID string `json:"id"`
		}
		json.NewDecoder(guildsResp.Body).Decode(&guilds)
		enc, err := sc.Encode("token", res)
		if err != nil {
			redirectLogin(w, r)
		}
		for _, g := range guilds {
			if *config.DiscordGuildID == g.ID {
				http.SetCookie(w, &http.Cookie{
					Name:     "token",
					Value:    enc,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
					Domain:   *config.DomainName,
					MaxAge:   300,
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

var sc securecookie.SecureCookie
var selfDomain string
var discordOauthConfig *oauth2.Config

func main() {
	config := loadConfig()
	fmt.Println(config)
	if cachedConfig.Subdomain != nil {
		selfDomain = fmt.Sprintf("https://%s.%s/", *config.Subdomain, *config.DomainName)
	} else {
		selfDomain = fmt.Sprintf("https://%s/", *config.DomainName)
	}

	discordOauthConfig = &oauth2.Config{
		ClientID:     *config.DiscordClientID,
		ClientSecret: *config.DiscordClientSecret,
		Scopes:       []string{"identify", "guilds"},
		Endpoint:     discordEndpoints,
	}
	if config.BlockKey == nil || config.HashKey == nil {
		sc = *securecookie.New(getRandBytes(32), getRandBytes(32))
	} else {
		hashKey, _ := base64.StdEncoding.DecodeString(*config.HashKey)
		blockKey, _ := base64.StdEncoding.DecodeString(*config.BlockKey)
		sc = *securecookie.New(hashKey, blockKey)
	}
	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/callback/{provider}", callbackHandler)
	fmt.Println("listening on port:", *config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", *config.Port), nil))
}
