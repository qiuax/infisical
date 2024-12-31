# Infisical Go Client Library

A Go client library for managing secrets stored in Infisical. This library provides the following features:

- Fetch and store secrets from Infisical
- Error handling and retry mechanisms
- Secret change notifications
- Thread-safe implementation
- Automatic token refresh

## Installation

```bash
go get github.com/yourusername/infisical
```

## Usage

```go
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
        SiteURL:         "YOUR_INFISICAL_URL",
        ClientId:        "YOUR_CLIENT_ID",
        ClientSecret:    "YOUR_CLIENT_SECRET",
        ProjectId:       "YOUR_PROJECT_ID",
        Environment:     "dev",
        RefreshInterval: 30 * time.Second,
    }

    // Create client
    client, err := client.NewClient(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Get secret
    secret, err := client.GetSecret("YOUR_SECRET_KEY")
    if err != nil {
        log.Printf("Error: %v", err)
    } else {
        log.Printf("Secret: %s = %s", secret.Key, secret.Value)
    }
}
```

## Features

### Automatic Refresh
The client periodically fetches the latest secrets from the Infisical server.

### Secret Change Notifications
You can register callback functions to listen for secret changes:

```go
client.RegisterCallback(func(secret *models.Secret) {
    log.Printf("Secret changed: %s", secret.Key)
})
```

### Error Handling and Retry
Built-in error handling and retry mechanism using exponential backoff strategy.

### Thread Safety
All operations are thread-safe and can be safely used across multiple goroutines.

## Configuration Options

- `SiteURL`: Infisical server address
- `ClientId`: Client ID for authentication
- `ClientSecret`: Client secret for authentication
- `ProjectId`: Project ID
- `Environment`: Environment (e.g., dev, staging, prod)
- `SecretPath`: Secret path
- `RefreshInterval`: Refresh interval for fetching latest secrets
- `MaxRetries`: Maximum number of retry attempts
- `Debug`: Enable debug mode

## Error Handling

The library provides detailed error information through custom error types:

```go
if err != nil {
    if e, ok := err.(*errors.Error); ok {
        log.Printf("Error Code: %s, Message: %s", e.Code, e.Message)
    }
}
```

## Best Practices

1. Always close the client when it's no longer needed:
```go
defer client.Close()
```

2. Handle secret change notifications appropriately:
```go
client.RegisterCallback(func(secret *models.Secret) {
    // Handle secret changes in a thread-safe manner
})
```

3. Configure appropriate refresh intervals based on your needs:
```go
cfg := config.Config{
    RefreshInterval: 1 * time.Minute,  // Adjust based on your requirements
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT 