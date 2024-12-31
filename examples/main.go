package main

import (
	"log"
	"time"

	"infisical/pkg/client"
	"infisical/pkg/config"
)

func main() {
	// Create configuration
	cfg := config.Config{
		SiteURL:         "http://127.0.0.1:8888",
		ClientId:        "e90ac9a4-c6f3-4ec0-bf42-912ad9483693",
		ClientSecret:    "1cbea4e19812b9415be22a15bdbea33f7848b60c6241648dda66e95d4f93ba63",
		ProjectId:       "6d7bdea8-1073-46a5-9e81-cd7ad4c71d71",
		Environment:     "dev",
		SecretPath:      "/",
		RefreshInterval: 5 * time.Second,
		MaxRetries:      3,
	}

	// Create client
	client, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Subscribe to secret updates
	//secretChan := client.NotifyUpdateOn("/test/api", "/test/db")
	secretChan := client.NotifyUpdateOn("/")
	defer client.Unsubscribe(secretChan)

	// Get secret
	secret, err := client.GetSecret("/", "TEST_KEY1")
	if err != nil {
		log.Printf("Failed to get secret: %v", err)
	} else {
		log.Printf("Secret value: %s = %s", secret.Key, secret.Value)
	}

	// Listen for secret updates
	go func() {
		for secret := range secretChan {
			log.Printf("Secret updated: Path=%s, Key=%s, Value=%s",
				secret.Path, secret.Key, secret.Value)
		}
	}()

	// Keep the program running to observe secret changes
	select {}
}
