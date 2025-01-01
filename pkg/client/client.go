package client

import (
	"context"
	"fmt"
	"log"
	"path"
	"regexp"
	"sync"
	"time"

	infisical "github.com/infisical/go-sdk"
	"infisical/pkg/config"
	"infisical/pkg/errors"
	"infisical/pkg/models"
)

// subscription represents a secret subscription
type subscription struct {
	patterns []*regexp.Regexp // regex patterns for path matching
	channel  chan models.Secret
}

// Client represents the main structure of the Infisical client
type Client struct {
	client        infisical.InfisicalClientInterface
	config        config.Config
	secrets       map[string]*models.Secret
	mu            sync.RWMutex
	refreshTicker *time.Ticker
	ctx           context.Context
	cancel        context.CancelFunc

	// Subscription management
	subscriptions []*subscription
	subMu         sync.RWMutex

	// Initialization flag
	initialized chan struct{}
}

// NewClient creates a new client instance
func NewClient(cfg config.Config) (*Client, error) {
	if cfg.ClientId == "" {
		return nil, errors.NewError(errors.ErrCodeConfigInvalid, "client ID is required", nil)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          cfg.SiteURL,
		AutoTokenRefresh: true,
	})

	// Authenticate using UniversalAuthLogin
	_, err := client.Auth().UniversalAuthLogin(cfg.ClientId, cfg.ClientSecret)
	if err != nil {
		cancel()
		return nil, errors.NewError(errors.ErrCodeAuthFailed, "failed to authenticate", err)
	}

	c := &Client{
		client:        client,
		config:        cfg,
		secrets:       make(map[string]*models.Secret),
		ctx:           ctx,
		cancel:        cancel,
		subscriptions: make([]*subscription, 0),
		initialized:   make(chan struct{}),
	}

	// Initialize secrets
	if err := c.refreshSecrets(); err != nil {
		cancel()
		return nil, err
	}
	close(c.initialized) // Mark initialization as complete

	// Start automatic refresh
	c.startRefreshing()

	return c, nil
}

// NotifyUpdateOn subscribes to updates for specific secret paths
func (c *Client) NotifyUpdateOn(paths ...string) chan models.Secret {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return nil
	}

	ch := make(chan models.Secret, 100) // Buffer size of 100

	sub := &subscription{
		patterns: make([]*regexp.Regexp, 0, len(paths)),
		channel:  ch,
	}

	for _, p := range paths {
		// Compile the pattern, if compilation fails, treat it as a literal path
		pattern, err := regexp.Compile(p)
		if err != nil {
			// If not a valid regex, escape special characters and compile as literal
			pattern = regexp.MustCompile(regexp.QuoteMeta(p))
		}
		sub.patterns = append(sub.patterns, pattern)
	}

	c.subMu.Lock()
	c.subscriptions = append(c.subscriptions, sub)
	c.subMu.Unlock()

	return ch
}

// Unsubscribe removes a subscription
func (c *Client) Unsubscribe(ch chan models.Secret) {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	for i, sub := range c.subscriptions {
		if sub.channel == ch {
			// Close the channel
			close(sub.channel)
			// Remove the subscription
			c.subscriptions = append(c.subscriptions[:i], c.subscriptions[i+1:]...)
			return
		}
	}
}

// GetSecret retrieves a specific secret by path and key directly from Infisical server
func (c *Client) GetSecret(secretPath string, key string) (*models.Secret, error) {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return nil, errors.NewError(errors.ErrCodeNetworkError, "client closed", nil)
	}

	// Directly fetch from Infisical server
	secret, err := c.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:   key,
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  secretPath,
	})

	if err != nil {
		return nil, errors.NewError(errors.ErrCodeSecretNotFound, fmt.Sprintf("failed to retrieve secret: %s", key), err)
	}

	// Convert to internal Secret model
	return &models.Secret{
		Key:       secret.SecretKey,
		Value:     secret.SecretValue,
		Type:      secret.Type,
		Path:      secret.SecretPath,
		UpdatedAt: time.Now(),
	}, nil
}

// Close shuts down the client
func (c *Client) Close() {
	c.cancel()
	if c.refreshTicker != nil {
		c.refreshTicker.Stop()
	}

	// Close all subscription channels
	c.subMu.Lock()
	for _, sub := range c.subscriptions {
		close(sub.channel)
	}
	c.subscriptions = nil
	c.subMu.Unlock()
}

// refreshSecrets fetches and updates secrets from the server
func (c *Client) refreshSecrets() error {
	// Get all subscribed paths and build a pattern map
	c.subMu.RLock()
	paths := make(map[string]bool)
	// Create a map to store all patterns and their associated channels
	patternMap := make(map[*regexp.Regexp][]chan models.Secret)
	for _, sub := range c.subscriptions {
		for _, pattern := range sub.patterns {
			// For regex patterns that match root or subdirectories
			if pattern.String() == ".*" || pattern.String() == "/.+" {
				paths["/"] = true
			} else {
				// Extract the actual path from the pattern
				patternStr := pattern.String()
				if path.Dir(patternStr) != "." {
					paths[path.Dir(patternStr)] = true
				} else {
					paths[patternStr] = true
				}
			}
			// Store the pattern and its channel
			patternMap[pattern] = append(patternMap[pattern], sub.channel)
		}
	}
	c.subMu.RUnlock()

	// Create new secrets map for subscribed secrets only
	newSecrets := make(map[string]*models.Secret)

	// Helper function to check if a secret matches any pattern and notify subscribers
	matchAndNotify := func(secret *models.Secret, action string) bool {
		matched := false
		for pattern, channels := range patternMap {
			if pattern.MatchString(secret.Path) {
				matched = true
				// Notify all channels interested in this pattern
				for _, ch := range channels {
					select {
					case ch <- *secret:
					default:
						// Channel is full, skip this update
					}
				}
			}
		}
		return matched
	}

	// Fetch secrets for each path
	for secretPath := range paths {
		secrets, err := c.client.Secrets().List(infisical.ListSecretsOptions{
			Environment: c.config.Environment,
			ProjectID:   c.config.ProjectId,
			SecretPath:  secretPath,
		})

		if err != nil {
			return errors.NewError(errors.ErrCodeNetworkError, fmt.Sprintf("failed to refresh secrets for path %s", secretPath), err)
		}

		// Process secrets for this path
		for _, s := range secrets {
			secretPath := models.ParseSecretPath(s.SecretPath)
			fullPath := path.Join(secretPath.FullPath(), s.SecretKey)
			newSecret := &models.Secret{
				Key:       s.SecretKey,
				Value:     s.SecretValue,
				Type:      s.Type,
				Path:      s.SecretPath,
				UpdatedAt: time.Now(),
			}

			// Check if any subscriber is interested and notify them
			if matchAndNotify(newSecret, models.SecretActionCreated) {
				// Check for changes in subscribed secrets
				oldSecret, exists := c.secrets[fullPath]
				if exists && oldSecret.Value != newSecret.Value {
					matchAndNotify(newSecret, models.SecretActionUpdated)
				}
				newSecrets[fullPath] = newSecret
			}
		}
	}

	// Check for deleted secrets
	for fullPath, oldSecret := range c.secrets {
		if _, exists := newSecrets[fullPath]; !exists {
			// Only notify if the secret was subscribed
			matchAndNotify(oldSecret, models.SecretActionDeleted)
		}
	}

	// Update secrets store with only subscribed secrets
	c.mu.Lock()
	c.secrets = newSecrets
	c.mu.Unlock()

	return nil
}

// startRefreshing starts the periodic refresh process
func (c *Client) startRefreshing() {
	c.refreshTicker = time.NewTicker(c.config.RefreshInterval)

	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.refreshTicker.C:
				if err := c.refreshSecrets(); err != nil {
					c.retryRefresh()
				}
			}
		}
	}()
}

// retryRefresh implements the retry mechanism
func (c *Client) retryRefresh() {
	backoff := time.Second

	for i := 0; i < c.config.MaxRetries; i++ {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
			if err := c.refreshSecrets(); err == nil {
				return
			}
			backoff *= 2 // Exponential backoff
		}
	}
}

// notifySubscribers sends updates to interested subscribers
func (c *Client) notifySubscribers(secret *models.Secret, action string) {
	c.subMu.RLock()
	defer c.subMu.RUnlock()

	for _, sub := range c.subscriptions {
		// Check if any pattern matches the secret path
		matched := false
		for _, pattern := range sub.patterns {
			if pattern.MatchString(secret.Path) {
				matched = true
				break
			}
		}

		if matched {
			// Non-blocking send
			select {
			case sub.channel <- *secret:
			default:
				// Channel is full, skip this update for this subscriber
			}
		}
	}

}

// SetSecret creates or updates a secret in Infisical
func (c *Client) SetSecret(secretPath string, key string, value string) error {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return errors.NewError(errors.ErrCodeNetworkError, "client closed", nil)
	}

	// First try to retrieve the secret to check if it exists
	_, err := c.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:   key,
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  secretPath,
	})

	if err != nil {
		// Secret doesn't exist, create a new one
		_, err = c.client.Secrets().Create(infisical.CreateSecretOptions{
			ProjectID:   c.config.ProjectId,
			Environment: c.config.Environment,
			SecretKey:   key,
			SecretValue: value,

			SecretPath: secretPath,
		})
	} else {
		// Secret exists, update it
		_, err = c.client.Secrets().Update(infisical.UpdateSecretOptions{
			SecretKey:      key,
			NewSecretValue: value,
			Environment:    c.config.Environment,
			ProjectID:      c.config.ProjectId,
			SecretPath:     secretPath,
		})
	}

	if err != nil {
		return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to set secret: %s", key), err)
	}

	// Trigger a refresh to update subscribers if any
	go c.refreshSecrets()

	return nil
}

// DeleteSecret deletes a secret from Infisical
func (c *Client) DeleteSecret(secretPath string, key string) error {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return errors.NewError(errors.ErrCodeNetworkError, "client closed", nil)
	}

	// Delete secret directly from Infisical
	mc, err := c.client.Secrets().Delete(infisical.DeleteSecretOptions{
		SecretKey:   key,
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  secretPath,
	})
	log.Printf("------>%+v", mc)
	if err != nil {
		return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to delete secret: %s", key), err)
	}

	// Trigger a refresh to update subscribers if any
	go c.refreshSecrets()

	return nil
}
