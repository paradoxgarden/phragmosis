package main

import (
	// "fmt"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
)

func loadFile(path string) []byte {
	dat, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("File not found at:", path)
	}
	return dat
}
var discord_redirect_string = "https://discord.com/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=https://%s/auth&scope=guilds"
func loginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("./static/login.html"))
	tmpl.Execute(w, map[string]string{
		"DiscordRedirect": fmt.Sprintf(discord_redirect_string, cfg["discord_client_id"], cfg["hostname"]),
		"ATProtoRedirect": "",
	})

}

// callback url
func goodHandler(w http.ResponseWriter, r *http.Request) {

}
func badHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(loadFile("./static/bad.html"))
}

var cfg map[string]interface{}

func main() {

	if err := json.Unmarshal(loadFile("./config.json"), &cfg); err != nil {
		panic(err)
	}
	fmt.Println(cfg)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/good", goodHandler)
	http.HandleFunc("/bad", badHandler)
	log.Fatal(http.ListenAndServe(":10999", nil))
}
