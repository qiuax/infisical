package client

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	infisical "github.com/infisical/go-sdk"
	"infisical/pkg/config"
	"infisical/pkg/errors"
	"infisical/pkg/models"
)

// subscription represents a secret subscription
type subscription struct {
	paths   map[string]bool // paths that this subscription is interested in
	channel chan models.Secret
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
		paths:   make(map[string]bool),
		channel: ch,
	}

	for _, p := range paths {
		sub.paths[p] = true
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
	secrets, err := c.client.Secrets().List(infisical.ListSecretsOptions{
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  c.config.SecretPath,
	})

	if err != nil {
		return errors.NewError(errors.ErrCodeNetworkError, "failed to refresh secrets", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Create new secrets map
	newSecrets := make(map[string]*models.Secret)

	// Process all secrets
	for _, s := range secrets {
		secretPath := models.ParseSecretPath(s.SecretPath)
		fullPath := secretPath.FullPath()
		fullPath = path.Join(fullPath, s.SecretKey)
		newSecret := &models.Secret{
			Key:       s.SecretKey,
			Value:     s.SecretValue,
			Type:      s.Type,
			Path:      s.SecretPath,
			UpdatedAt: time.Now(),
		}

		// Check for changes
		oldSecret, exists := c.secrets[fullPath]
		if exists && oldSecret.Value != newSecret.Value {
			c.notifySubscribers(newSecret, models.SecretActionUpdated)
		} else if !exists {
			c.notifySubscribers(newSecret, models.SecretActionCreated)
		}

		newSecrets[fullPath] = newSecret
	}

	// Check for deleted secrets
	for fullPath, oldSecret := range c.secrets {
		if _, exists := newSecrets[fullPath]; !exists {
			c.notifySubscribers(oldSecret, models.SecretActionDeleted)
		}
	}

	// Update secrets store
	c.secrets = newSecrets
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
		// Check if this subscriber is interested in this secret
		if sub.paths[secret.Path] || sub.paths[path.Dir(secret.Path)] {
			// Non-blocking send
			select {
			case sub.channel <- *secret:
			default:
				// Channel is full, skip this update for this subscriber
			}
		}
	}
}
