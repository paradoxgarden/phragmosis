package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

func loadFile(path string) []byte {
	dat, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("File not found at:", path)
	}
	return dat
}

var atproto_redirect_string = "https://?"

func loginHandler(w http.ResponseWriter, r *http.Request) {
	conf := &oauth2.Config{
		ClientID:     cfg["discord_client_id"].(string),
		ClientSecret: cfg["discord_client_secret"].(string),
		Scopes:       []string{"identify", "guilds"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
	verf := oauth2.GenerateVerifier()
	dat := make([]byte, 16)
	_, err := rand.Read(dat)
	if err != nil {
		panic(1)
	}
	state := base64.URLEncoding.EncodeToString(dat)
	url := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verf))
	tmpl := template.Must(template.ParseFiles("./static/login.html"))
	tmpl.Execute(w, map[string]string{
		"DiscordRedirect": url,
		"ATProtoRedirect": "",
	})
}
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")
		original_dest := "https://" + host + uri
		http.Redirect(w, r, fmt.Sprintf("https://%s/login?redirect=%s", cfg["hostname"], original_dest), http.StatusFound)

	}
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("provider")
	if from == "discord" {

		//oauth !
		return
	} else { // this is probably atproto but i'll get that exact url later
		return
	}
}

var cfg map[string]interface{}

func main() {

	if err := json.Unmarshal(loadFile("./config.json"), &cfg); err != nil {
		panic(err)
	}
	fmt.Println(cfg)
	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/callback/{provider}", callbackHandler)
	fmt.Println("listening on port:", cfg["port"])
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", cfg["port"].(string)), nil))
}
