package main

import (
	"log"
	"time"

	"github.com/hashmatoteam/infisical/pkg/client"
	"github.com/hashmatoteam/infisical/pkg/config"
)

func main() {
	// Create configuration
	cfg := config.Config{
		SiteURL:      "http://127.0.0.1:8888",
		ClientId:     "e90ac9a4-c6f3-4ec0-bf42-912ad9483693", // test_identity
		ClientSecret: "1cbea4e19812b9415be22a15bdbea33f7848b60c6241648dda66e95d4f93ba63",
		//
		//ClientId:        "faa74ccc-090f-4a47-b428-3b86b8030a92",
		//ClientSecret:    "c83a73cee47a98b12a5589d46104181ce34ad8c1687db23b7ec97d0215796398",
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
	secretChan := client.NotifyUpdateOn("/", "/test")
	//secretChan := client.NotifyUpdateOn("/")
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
				secret.Secret.Path, secret.Secret.Key, secret.Secret.Value)
		}
	}()

	// create or update
	//err = client.SetSecret("/", "API_KEY", "qwe123")
	err = client.SetSecret("/test", "API_KEY", "qwe12345")
	if err != nil {
		log.Printf("Failed to SetSecret: %v", err)
	} else {
		log.Println("SetSecret success")
	}
	// delete
	err = client.DeleteSecret("/test", "API_KEY")
	if err != nil {
		log.Printf("Failed to DeleteSecret : %v", err)
	} else {
		log.Println("DeleteSecret success")
	}
	// Keep the program running to observe secret changes

	// Subscribe to a specific catalog
	//client.NotifyUpdateOn("/api/v1")
	//
	//// Subscribe to all catalogs
	//client.NotifyUpdateOn(".*")
	//
	//// Subscribe to multiple directories
	//client.NotifyUpdateOn("/api/.*", "/db/.*")
	select {}
}
