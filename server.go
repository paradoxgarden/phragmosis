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

var discord_endpoints = oauth2.Endpoint{
	AuthURL:  "https://discord.com/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	config := loadConfig()
	conf := &oauth2.Config{
		ClientID:     *config.DiscordClientID,
		ClientSecret: *config.DiscordClientSecret,
		Scopes:       []string{"identify", "guilds"},
		Endpoint:     discord_endpoints,
	}
	dat := getRandBytes(16)
	verf := oauth2.GenerateVerifier()
	state := base64.URLEncoding.EncodeToString(dat)
	enc, _ := sc.Encode("oauth_meta", map[string]string{
		"state":    state,
		"verf":     verf,
		"redirect": r.URL.Query().Get("redirect"),
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
	url := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verf))
	tmpl := template.Must(template.ParseFiles("./static/login.html"))
	tmpl.Execute(w, map[string]string{
		"DiscordRedirect": url,
		"ATProtoRedirect": "",
	})
}
func authHandler(w http.ResponseWriter, r *http.Request) {
	config := loadConfig()
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	originalDest := "https://" + host + uri
	cookie, err := r.Cookie("token")

	if err != http.ErrNoCookie {
		var auth map[string]interface{}
		err = sc.Decode("token", cookie.Value, &auth)
		if err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		if config.Subdomain != nil {
			http.Redirect(w, r, fmt.Sprintf("https://%s.%s/login?redirect=%s", *config.Subdomain, config.DomainName, originalDest), http.StatusFound)
			return
		} else {
			http.Redirect(w, r, fmt.Sprintf("https://%s/login?redirect=%s", config.DomainName, originalDest), http.StatusFound)
			return
		}
	}
	if config.Subdomain != nil {
		http.Redirect(w, r, fmt.Sprintf("https://%s.%s/login?redirect=%s", *config.Subdomain, config.DomainName, originalDest), http.StatusFound)
		return
	} else {
		http.Redirect(w, r, fmt.Sprintf("https://%s/login?redirect=%s", config.DomainName, originalDest), http.StatusFound)
		return
	}
}

var sc securecookie.SecureCookie

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	config := loadConfig()
	from := r.PathValue("provider")
	if from == "discord" {
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

		req, _ := http.NewRequest("POST", discord_endpoints.TokenURL, strings.NewReader(payload.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(*config.DiscordClientID, *config.DiscordClientSecret)
		resp, _ := http.DefaultClient.Do(req)
		defer resp.Body.Close()
		var res map[string]interface{}

		json.NewDecoder(resp.Body).Decode(&res)
		req, _ = http.NewRequest("GET", "https://discord.com/api/users/@me/guilds", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", res["access_token"]))
		guildsResp, _ := http.DefaultClient.Do(req)
		var guilds []struct {
			ID string `json:"id"`
		}
		json.NewDecoder(guildsResp.Body).Decode(&guilds)
		enc, _ := sc.Encode("token", res)
		for _, g := range guilds {
			if *config.DiscordGuildID == g.ID {
				http.SetCookie(w, &http.Cookie{
					Name:     "token",
					Value:    enc,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
					Domain:   config.DomainName,
					MaxAge:   300,
				})
				http.Redirect(w, r, oauth_meta["redirect"], http.StatusFound)
				return
			}
		}

	}
}

func main() {
	config := loadConfig()
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
	fmt.Println("listening on port:", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil))
}
