package config

import "time"

// Config defines the configuration options for the Infisical client
type Config struct {
	// Infisical server address
	SiteURL string
	// ClientId for authentication
	ClientId string
	// ClientSecret for authentication
	ClientSecret string
	// Environment (e.g., dev, staging, prod)
	Environment string
	// Project ID
	ProjectId string
	// Secret path
	SecretPath string
	// Refresh interval for fetching latest secrets from server
	RefreshInterval time.Duration
	// Maximum number of retry attempts
	MaxRetries int
	// Enable debug mode
	Debug bool
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		SiteURL:         "https://app.infisical.com",
		Environment:     "dev",
		SecretPath:      "/",
		RefreshInterval: 60 * time.Second,
		MaxRetries:      3,
		Debug:           false,
	}
}
