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

	// If no paths specified or contains root path, subscribe to all paths
	for _, p := range paths {
		if p == "/" || p == ".*" || p == "/.+" {
			// Subscribe to all paths
			sub.patterns = append(sub.patterns, regexp.MustCompile(".*"))
			c.subMu.Lock()
			c.subscriptions = append(c.subscriptions, sub)
			c.subMu.Unlock()
			return ch
		}
	}

	// Otherwise, compile patterns for specific paths
	for _, p := range paths {
		// If path contains wildcards, ensure it's properly formatted for regex
		pattern := p
		if containsWildcard(p) {
			// Escape all special characters except wildcards
			pattern = escapeExceptWildcards(p)
		} else {
			// For exact paths, match the path and all its subpaths
			pattern = regexp.QuoteMeta(p) + "($|/.*)"
		}

		compiledPattern, err := regexp.Compile(pattern)
		if err != nil {
			// If compilation fails, treat it as a literal path
			compiledPattern = regexp.MustCompile(regexp.QuoteMeta(p) + "($|/.*)")
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

// listAllSecrets recursively lists all secrets in a path and its subfolders
func (c *Client) listAllSecrets(folderPath string) ([]*infisical.Secret, error) {
	var allSecrets []*infisical.Secret

	// Get secrets in current path
	secrets, err := c.client.Secrets().List(infisical.ListSecretsOptions{
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  folderPath,
	})
	if err != nil {
		// If we get an error and it's not because the folder doesn't exist, return it
		if apiErr, ok := err.(*infisical.APIError); !ok || !strings.Contains(apiErr.ErrorMessage, "Folder not found") {
			return nil, err
		}
		// If folder not found, just return empty list
		return allSecrets, nil
	}

	// Convert current path secrets to pointers and add to result
	for i := range secrets {
		allSecrets = append(allSecrets, &secrets[i])
	}

	// Get subfolders
	folders, err := c.client.Folders().List(infisical.ListFoldersOptions{
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		Path:        folderPath,
	})
	if err != nil {
		// If we get an error listing folders, just return the secrets we have
		log.Printf("Error listing folders for path %s: %v", folderPath, err)
		return allSecrets, nil
	}

	// Recursively get secrets from each subfolder
	for _, folder := range folders {
		subfolderPath := path.Join(folderPath, folder.Name)
		subSecrets, err := c.listAllSecrets(subfolderPath)
		if err != nil {
			// Log the error but continue with other folders
			log.Printf("Error listing secrets in folder %s: %v", subfolderPath, err)
			continue
		}
		allSecrets = append(allSecrets, subSecrets...)
	}

	return allSecrets, nil
}

// refreshSecrets fetches and updates secrets from the server
func (c *Client) refreshSecrets() error {
	// Get all secrets recursively starting from root
	secrets, err := c.listAllSecrets("/")
	if err != nil {
		if apiErr, ok := err.(*infisical.APIError); ok && strings.Contains(apiErr.ErrorMessage, "Rate limit exceeded") {
			// If rate limited, skip this refresh
			log.Printf("Rate limit exceeded during refresh, skipping this cycle")
			return nil
		}
		return errors.NewError(errors.ErrCodeNetworkError, "failed to refresh secrets", err)
	}

	// Create new secrets map
	newSecrets := make(map[string]*models.Secret)

	// Process all secrets
	for _, s := range secrets {
		// 确保 SecretPath 不为空
		secretPath := s.SecretPath
		if secretPath == "" {
			secretPath = "/"
		}

		fullPath := path.Join(secretPath, s.SecretKey)
		newSecret := &models.Secret{
			Key:       s.SecretKey,
			Value:     s.SecretValue,
			Type:      s.Type,
			Path:      secretPath,
			UpdatedAt: time.Now(),
		}

		oldSecret, exists := c.secrets[fullPath]
		if !exists {
			// New secret
			c.notifySubscribers(newSecret, models.SecretActionCreated)
		} else if oldSecret.Value != newSecret.Value {
			// Updated secret
			c.notifySubscribers(newSecret, models.SecretActionUpdated)
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
	c.mu.Lock()
	c.secrets = newSecrets
	c.mu.Unlock()

	return nil
}

// startRefreshing starts the periodic refresh process
func (c *Client) startRefreshing() {
	// 设置一个较长的刷新间隔，默认为 30 秒
	refreshInterval := c.config.RefreshInterval
	if refreshInterval < 30*time.Second {
		refreshInterval = 30 * time.Second
	}
	c.refreshTicker = time.NewTicker(refreshInterval)

	var lastRefreshTime time.Time
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.refreshTicker.C:
				// 如果距离上次刷新时间太短，跳过本次刷新
				if time.Since(lastRefreshTime) < 5*time.Second {
					continue
				}

				if err := c.refreshSecrets(); err != nil {
					if apiErr, ok := err.(*infisical.APIError); ok && strings.Contains(apiErr.ErrorMessage, "Rate limit exceeded") {
						// 如果遇到速率限制，停止当前的 ticker 并创建一个新的
						c.refreshTicker.Stop()
						refreshInterval = refreshInterval * 2
						c.refreshTicker = time.NewTicker(refreshInterval)
						log.Printf("Rate limit hit, increasing refresh interval to %v", refreshInterval)
						continue
					}
					c.retryRefresh()
				}
				lastRefreshTime = time.Now()
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

// createFolder creates a folder at the specified path if it doesn't exist
func (c *Client) createFolder(folderPath string) error {
	// Ensure path starts with "/"
	if !strings.HasPrefix(folderPath, "/") {
		folderPath = "/" + folderPath
	}

	// If it's root path, no need to create
	if folderPath == "/" {
		return nil
	}

	// Split the path into components
	components := strings.Split(strings.Trim(folderPath, "/"), "/")
	if len(components) == 0 {
		return nil
	}

	// Start from the beginning of the path
	currentPath := ""
	for _, component := range components {
		// Build the current path
		if currentPath == "" {
			currentPath = "/" + component
		} else {
			currentPath = path.Join(currentPath, component)
		}

		// Try to create this folder
		name := component
		parentPath := path.Dir(currentPath)
		if parentPath == "/" {
			parentPath = ""
		}

		_, err := c.client.Folders().Create(infisical.CreateFolderOptions{
			ProjectID:   c.config.ProjectId,
			Environment: c.config.Environment,
			Name:        name,
			Path:        parentPath,
		})

		// If we get an error and it's not because the folder already exists, return it
		if err != nil {
			// Check if it's an APIError indicating the folder already exists
			if apiErr, ok := err.(*infisical.APIError); !ok || !strings.Contains(apiErr.ErrorMessage, "already exists") {
				return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to create folder: %s", currentPath), err)
			}
			// If folder already exists, continue to next component
		}
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

	// First ensure the folder path exists
	if secretPath != "/" {
		if err := c.createFolder(secretPath); err != nil {
			return err
		}
	}

	// Try to retrieve the secret to check if it exists
	_, err := c.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:   key,
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  secretPath,
	})

	var newSecret *models.Secret
	if err != nil {
		// Try to create the secret since it doesn't exist
		secret, err := c.client.Secrets().Create(infisical.CreateSecretOptions{
			ProjectID:   c.config.ProjectId,
			Environment: c.config.Environment,
			SecretKey:   key,
			SecretValue: value,
			SecretPath:  secretPath,
		})

		if err != nil {
			return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to create secret: %s", key), err)
		}

		newSecret = &models.Secret{
			Key:       secret.SecretKey,
			Value:     secret.SecretValue,
			Type:      secret.Type,
			Path:      secretPath,
			UpdatedAt: time.Now(),
		}
		// Notify subscribers about the new secret
		c.notifySubscribers(newSecret, models.SecretActionCreated)
	} else {
		// Secret exists, update it
		secret, err := c.client.Secrets().Update(infisical.UpdateSecretOptions{
			SecretKey:      key,
			NewSecretValue: value,
			Environment:    c.config.Environment,
			ProjectID:      c.config.ProjectId,
			SecretPath:     secretPath,
		})

		if err != nil {
			return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to update secret: %s", key), err)
		}

		newSecret = &models.Secret{
			Key:       secret.SecretKey,
			Value:     secret.SecretValue,
			Type:      secret.Type,
			Path:      secretPath,
			UpdatedAt: time.Now(),
		}
		// Notify subscribers about the updated secret
		c.notifySubscribers(newSecret, models.SecretActionUpdated)
	}

	// Update the secret in our local cache
	c.mu.Lock()
	fullPath := path.Join(secretPath, key)
	c.secrets[fullPath] = newSecret
	c.mu.Unlock()

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
	_, err := c.client.Secrets().Delete(infisical.DeleteSecretOptions{
		SecretKey:   key,
		Environment: c.config.Environment,
		ProjectID:   c.config.ProjectId,
		SecretPath:  secretPath,
	})
	if err != nil {
		return errors.NewError(errors.ErrCodeSecretUpdateFailed, fmt.Sprintf("failed to delete secret: %s", key), err)
	}

	// Remove from local cache and notify subscribers
	c.mu.Lock()
	fullPath := path.Join(secretPath, key)
	if oldSecret, exists := c.secrets[fullPath]; exists {
		delete(c.secrets, fullPath)
		c.mu.Unlock()
		c.notifySubscribers(oldSecret, models.SecretActionDeleted)
	} else {
		c.mu.Unlock()
	}

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
			patternStr := pattern.String()

			// For root path subscription ("/"), match everything
			if patternStr == "/" || patternStr == ".*" || patternStr == "/.+" {
				matchingChannels = append(matchingChannels, sub.channel)
				break
			}

			// For exact path matches
			if !containsWildcard(patternStr) {
				// If the pattern is an exact path, it should match either:
				// 1. The exact secret path
				// 2. Any secret under this path
				if strings.HasPrefix(secret.Path, patternStr+"/") || secret.Path == patternStr {
					matchingChannels = append(matchingChannels, sub.channel)
					break
				}
				continue
			}

			// For wildcard patterns
			if pattern.MatchString(secret.Path) {
				matchingChannels = append(matchingChannels, sub.channel)
				break
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
