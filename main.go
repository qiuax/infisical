package main

import (
	"context"
	"fmt"
	infisical "github.com/infisical/go-sdk"
	"os"
)

func main() {

	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl:          "http://127.0.0.1:8888", // Optional, default is https://app.infisical.com
		AutoTokenRefresh: true,                    // Wether or not to let the SDK handle the access token lifecycle. Defaults to true if not specified.
	})

	_, err := client.Auth().UniversalAuthLogin("e90ac9a4-c6f3-4ec0-bf42-912ad9483693", "1cbea4e19812b9415be22a15bdbea33f7848b60c6241648dda66e95d4f93ba63")

	if err != nil {
		fmt.Printf("Authentication failed: %v", err)
		os.Exit(1)
	}

	apiKeySecret, err := client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:   "TEST_KEY",
		Environment: "dev",
		ProjectID:   "6d7bdea8-1073-46a5-9e81-cd7ad4c71d71",
		SecretPath:  "/",
	})

	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("API Key Secret: %+v", apiKeySecret)

}
