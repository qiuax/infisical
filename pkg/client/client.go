package client

import (
	"context"
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashmatoteam/infisical/pkg/config"
	"github.com/hashmatoteam/infisical/pkg/errors"
	"github.com/hashmatoteam/infisical/pkg/models"
	infisical "github.com/infisical/go-sdk"
)

// subscription represents a secret subscription
type subscription struct {
	patterns []*regexp.Regexp // regex patterns for path matching
	channel  chan models.SecretEvent
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
func (c *Client) NotifyUpdateOn(paths ...string) chan models.SecretEvent {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return nil
	}

	ch := make(chan models.SecretEvent, 100) // Buffer size of 100

	sub := &subscription{
		patterns: make([]*regexp.Regexp, 0, len(paths)),
		channel:  ch,
	}

	for _, p := range paths {
		// If path contains wildcards, ensure it's properly formatted for regex
		pattern := p
		if containsWildcard(p) {
			// Escape all special characters except wildcards
			pattern = escapeExceptWildcards(p)
		} else {
			pattern = regexp.QuoteMeta(p)
		}

		compiledPattern, err := regexp.Compile(pattern)
		if err != nil {
			// If compilation fails, treat it as a literal path
			compiledPattern = regexp.MustCompile(regexp.QuoteMeta(p))
		}
		sub.patterns = append(sub.patterns, compiledPattern)
	}

	c.subMu.Lock()
	c.subscriptions = append(c.subscriptions, sub)
	c.subMu.Unlock()

	return ch
}

// Unsubscribe removes a subscription
func (c *Client) Unsubscribe(ch chan models.SecretEvent) {
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
	for _, sub := range c.subscriptions {
		for _, pattern := range sub.patterns {
			patternStr := pattern.String()
			// Handle different wildcard cases
			switch {
			case patternStr == "/" || patternStr == ".*" || patternStr == "/.+":
				// Match everything
				paths["/"] = true
			case containsWildcard(patternStr):
				// For patterns with wildcards, we need to fetch from the root directory
				// that contains the wildcard
				rootPath := getRootPath(patternStr)
				paths[rootPath] = true
			default:
				// For literal paths, add both the path itself and its parent
				if path.Dir(patternStr) != "." {
					paths[path.Dir(patternStr)] = true
					paths[patternStr] = true
				} else {
					paths[patternStr] = true
				}
			}
		}
	}
	c.subMu.RUnlock()

	// Create new secrets map for subscribed secrets only
	newSecrets := make(map[string]*models.Secret)

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

			// Check if any subscriber is interested in this secret
			if channels := c.matchSecretWithPatterns(newSecret); len(channels) > 0 {
				oldSecret, exists := c.secrets[fullPath]
				if !exists {
					// New secret
					c.notifyChannels(newSecret, channels, models.SecretActionCreated)
				} else if oldSecret.Value != newSecret.Value {
					// Updated secret
					c.notifyChannels(newSecret, channels, models.SecretActionUpdated)
				}
				newSecrets[fullPath] = newSecret
			}
		}
	}

	// Check for deleted secrets
	for fullPath, oldSecret := range c.secrets {
		if _, exists := newSecrets[fullPath]; !exists {
			if channels := c.matchSecretWithPatterns(oldSecret); len(channels) > 0 {
				c.notifyChannels(oldSecret, channels, models.SecretActionDeleted)
			}
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

	event := models.SecretEvent{
		Secret: secret,
		Action: action,
	}

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
			case sub.channel <- event:
			default:
				// Channel is full, skip this update for this subscriber
			}
		}
	}
}

// createFolder creates a folder at the specified path if it doesn't exist
func (c *Client) createFolder(folderPath string) error {
	// Ensure path starts with "/"
	if !strings.HasPrefix(folderPath, "/") {
		folderPath = "/" + folderPath
	}

	// Get the folder name from the path
	name := path.Base(folderPath)
	parentPath := path.Dir(folderPath)
	if parentPath == "/" {
		parentPath = ""
	}

	// Create folder using Infisical API
	_, err := c.client.Folders().Create(infisical.CreateFolderOptions{
		ProjectID:   c.config.ProjectId,
		Environment: c.config.Environment,
		Name:        name,
		Path:        parentPath,
	})
	if err != nil {
		return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to create folder: %s", folderPath), err)
	}
	return nil
}

// SetSecret creates or updates a secret in Infisical
func (c *Client) SetSecret(secretPath string, key string, value string) error {
	// Wait for initialization to complete
	select {
	case <-c.initialized:
	case <-c.ctx.Done():
		return errors.NewError(errors.ErrCodeNetworkError, "client closed", nil)
	}

	// First ensure the folder exists
	if secretPath != "/" {
		if err := c.createFolder(secretPath); err != nil {
			return err
		}
	}

	// Try to create the secret first
	_, err := c.client.Secrets().Create(infisical.CreateSecretOptions{
		ProjectID:   c.config.ProjectId,
		Environment: c.config.Environment,
		SecretKey:   key,
		SecretValue: value,
		SecretPath:  secretPath,
	})

	if err != nil {
		// If creation fails, try to update in case the secret already exists
		_, err = c.client.Secrets().Update(infisical.UpdateSecretOptions{
			SecretKey:      key,
			NewSecretValue: value,
			Environment:    c.config.Environment,
			ProjectID:      c.config.ProjectId,
			SecretPath:     secretPath,
		})

		if err != nil {
			return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to set secret: %s", key), err)
		}
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

// containsWildcard checks if a path contains any regex wildcard patterns
func containsWildcard(path string) bool {
	return strings.Contains(path, ".*") || strings.Contains(path, ".+") ||
		strings.Contains(path, "[") || strings.Contains(path, "?")
}

// getRootPath returns the root path before the first wildcard in the pattern
// For example: "/db/.*/tokens" returns "/db"
func getRootPath(pattern string) string {
	parts := strings.Split(pattern, "/")
	var rootParts []string

	for _, part := range parts {
		if containsWildcard(part) {
			break
		}
		if part != "" {
			rootParts = append(rootParts, part)
		}
	}

	if len(rootParts) == 0 {
		return "/"
	}
	return "/" + strings.Join(rootParts, "/")
}

// escapeExceptWildcards escapes all regex special characters except wildcards
func escapeExceptWildcards(pattern string) string {
	// First, escape all special regex characters
	escaped := regexp.QuoteMeta(pattern)

	// Replace escaped wildcards with their original form
	escaped = strings.ReplaceAll(escaped, `\.\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\.\+`, `.+`)

	return escaped
}

// matchSecretWithPatterns checks if a secret matches any subscription patterns and returns the matching channels
func (c *Client) matchSecretWithPatterns(secret *models.Secret) []chan models.SecretEvent {
	c.subMu.RLock()
	defer c.subMu.RUnlock()

	var matchingChannels []chan models.SecretEvent
	for _, sub := range c.subscriptions {
		for _, pattern := range sub.patterns {
			// For root path subscription ("/"), match everything
			if pattern.String() == "/" && strings.HasPrefix(secret.Path, "/") {
				matchingChannels = append(matchingChannels, sub.channel)
				break
			}
			// For other patterns
			if pattern.MatchString(secret.Path) {
				matchingChannels = append(matchingChannels, sub.channel)
				break // Once we find a match for this subscription, move to next one
			}
		}
	}
	return matchingChannels
}

// notifyChannels sends a secret event to all provided channels
func (c *Client) notifyChannels(secret *models.Secret, channels []chan models.SecretEvent, action string) {
	event := models.SecretEvent{
		Secret: secret,
		Action: action,
	}
	for _, ch := range channels {
		select {
		case ch <- event:
		default:
			// Channel is full, skip this update
		}
	}
}
