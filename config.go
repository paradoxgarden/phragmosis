package main

import (
	"encoding/json"
	"log"
	"os"
	"io"
	"time"
)

type Config struct {
	DidAllowList        []string `json:"didAllowList"`
	DiscordGuildID      *string   `json:discordGuildID`
	DiscordClientID     *string   `json:discordClientID`
	DiscordClientSecret *string   `json:discordClientSecret`
	TailscaleSock       *string   `json:tailscaleSock`
	DomainName          string   `json:domainName`
	Subdomain           *string  `json:subdomain`
	Port                string   `json:port`
	HashKey             *string  `json:hashKey`
	BlockKey            *string  `json:blockKey`
}

var cachedConfig Config
var configLastRead time.Time

// load precedence no overwrites
// ENV > config.json > generate
func loadConfig() *Config {
	var config Config
	path := "./config.json"
	info, _ := os.Stat("./config.json")
	if info.ModTime().Equal(configLastRead) {
		return &cachedConfig
	}
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("not enough resources to run!")
	}
	dat, err := io.ReadAll(file)
	if err != nil {
		log.Fatal("not enough resources to run!")
	}
	info, err = file.Stat()
	if err != nil {
		log.Fatal("not enough resources to run!")
	}
	file.Close()
	configLastRead = info.ModTime()
	err = json.Unmarshal(dat, &config)
	if err != nil {
		log.Fatal("not enough resources to run!")
	}
	cachedConfig = config
	return &config

}
