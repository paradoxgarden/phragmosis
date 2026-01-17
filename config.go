package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	DidAllowList        []string `json:"didAllowList"`
	DiscordGuildID      *string  `json:"discordGuildID"`
	DiscordClientID     *string  `json:"discordClientID"`
	DiscordClientSecret *string  `json:"discordClientSecret"`
	TailscaleSock       *string  `json:"tailscaleSock"`
	DomainName          *string  `json:"domainName"`
	Subdomain           *string  `json:"subdomain"`
	Port                *string  `json:"port"`
	HashKey             *string  `json:"hashKey"`
	BlockKey            *string  `json:"blockKey"`
}

var (
	cachedConfig  Config
	configLastMod *time.Time
	configMu      sync.Mutex
)

// load precedence no overwrites
// ENV > config.json > generate
func loadConfig() Config {
	configMu.Lock()
	defer configMu.Unlock()

	var c Config
	c = loadFromJson(c)
	c = loadFromEnv(c)

	cachedConfig = c
	return c

}
func loadFromEnv(c Config) Config {
	didList := os.Getenv("DID_ALLOW_LIST")
	if didList != "" {
		c.DidAllowList = strings.Split(didList, ",")
	}
	discordGuild := os.Getenv("DISCORD_GUILD_ID")
	if discordGuild != "" {
		c.DiscordGuildID = &discordGuild
	}
	discordClientID := os.Getenv("DISCORD_CLIENT_ID")
	if discordClientID != "" {
		c.DiscordClientID = &discordClientID
	}
	discordClientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	if discordClientSecret != "" {
		c.DiscordClientID = &discordClientSecret
	}
	tailscale := os.Getenv("TAILSCALE_SOCK")
	if tailscale != "" {
		c.TailscaleSock = &tailscale
	}
	domain := os.Getenv("DOMAIN_NAME")
	if domain != "" {
		c.DomainName = &domain
	}
	subdomain := os.Getenv("SUBDOMAIN")
	if subdomain != "" {
		c.Subdomain = &subdomain
	}
	port := os.Getenv("PORT")
	if port != "" {
		c.Port = &port
	}
	hash := os.Getenv("HASH_KEY")
	if hash != "" {
		c.HashKey = &hash
	}
	block := os.Getenv("BLOCK_KEY")
	if block != "" {
		c.BlockKey = &block
	}
	return c
}

func loadFromJson(c Config) Config {
	configPath := "./config.json"
	info, err := os.Stat(configPath)
	if err != nil {
		return c
	}
	lastMod := info.ModTime()
	if configLastMod != nil && lastMod.Equal(*configLastMod) {
		return cachedConfig
	}
	file, err := os.Open(configPath)
	if err != nil {
		return c
	}
	defer file.Close()
	dat, err := io.ReadAll(file)
	if err != nil {
		return c
	}
	configLastMod = &lastMod

	err = json.Unmarshal(dat, &c)
	if err != nil {
		return c
	}
	return c
}
