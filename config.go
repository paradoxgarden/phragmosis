package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type config struct {
	DidAllowList        []string `json:"didAllowList"`
	DiscordGuildID      *string  `json:"discordGuildID"`
	DiscordClientID     *string  `json:"discordClientID"`
	DiscordClientSecret *string  `json:"discordClientSecret"`
	TailscaleSock       *string  `json:"tailscaleSock"`
	DomainName          *string  `json:"domainName"`
	Subdomain           *string  `json:"subdomain"`
	Port                *string  `json:"port"`
	Debug               *bool    `json:"debug"`
	AllowedDomains      []string `json:"allowedDomains"`
	HashKey             *string  `json:"hashKey"`
	BlockKey            *string  `json:"blockKey"`
}

// load precedence
// generated keys < json < ENV
func loadConfig() (*config, error) {
	c := &config{}

	path := "./config.json"
	err := c.loadFromJson(path)
	if err != nil {
		slog.Info("./config.json not found, server will crash if env vars do not provide enough resources to run")
	}
	c.loadFromEnv(os.Getenv)
	err = c.validateConfig()
	if err != nil {
		return nil, err
	}
	return c, err
}
func (c *config) validateConfig() error {

	if c.Port != nil {
		_, err := strconv.Atoi(*c.Port)
		if err != nil {
			return fmt.Errorf("no port provided, unable to start server")
		}
	}
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("no allowed domains specified, server will not do anything")
	}
	if c.DomainName == nil {
		return fmt.Errorf("domain name unspecified, unable to start server")
	}
	if c.DiscordClientID == nil && c.DiscordClientSecret == nil && c.DiscordGuildID == nil &&
		c.DidAllowList == nil &&
		c.TailscaleSock == nil {
		return fmt.Errorf("no way to auth specified, server will not do anything")
	}
	if c.Debug == nil {
		c.Debug = new(bool)
		*c.Debug = false
	}
	return nil
}
func (c *config) loadFromEnv(env func(string) string) {
	didList := env("PHRAG_DID_ALLOW_LIST")
	if didList != "" {
		c.DidAllowList = strings.Split(didList, ",")
	}
	discordGuild := env("PHRAG_DISCORD_GUILD_ID")
	if discordGuild != "" {
		c.DiscordGuildID = &discordGuild
	}
	discordClientID := env("PHRAG_DISCORD_CLIENT_ID")
	if discordClientID != "" {
		c.DiscordClientID = &discordClientID
	}
	discordClientSecret := env("PHRAG_DISCORD_CLIENT_SECRET")
	if discordClientSecret != "" {
		c.DiscordClientSecret = &discordClientSecret
	}
	tailscale := env("PHRAG_TAILSCALE_SOCK")
	if tailscale != "" {
		c.TailscaleSock = &tailscale
	}
	domain := env("PHRAG_DOMAIN_NAME")
	if domain != "" {
		c.DomainName = &domain
	}
	subdomain := env("PHRAG_SUBDOMAIN")
	if subdomain != "" {
		c.Subdomain = &subdomain
	}
	port := env("PHRAG_PORT")
	if port != "" {
		c.Port = &port
	}
	debug := env("PHRAG_DEBUG")
	if debug != "" {
		b, _ := strconv.ParseBool(debug)
		// if parseBool throws an error it returns false, which is ok for debug
		c.Debug = new(bool)
		*c.Debug = b
	}
	hash := env("PHRAG_HASH_KEY")
	if hash != "" {
		c.HashKey = &hash
	}
	block := env("PHRAG_BLOCK_KEY")
	if block != "" {
		c.BlockKey = &block
	}
	allowedDomains := env("PHRAG_ALLOWED_DOMAINS")
	if allowedDomains != "" {
		c.AllowedDomains = strings.Split(allowedDomains, ",")
	}
}

func (c *config) loadFromJson(path string) error {
	dat, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(dat, &c)
	if err != nil {
		return err
	}
	return nil
}
