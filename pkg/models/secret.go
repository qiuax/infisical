package models

import (
	"path"
	"time"
)

// Secret represents a secret with its full path information
type Secret struct {
	Key       string
	Value     string
	Type      string
	Path      string // Full path including folders
	UpdatedAt time.Time
}

// SecretPath represents a parsed secret path
type SecretPath struct {
	Folder string // Folder path
	Key    string // Secret key
}

// ParseSecretPath parses a full path into folder and key components
func ParseSecretPath(fullPath string) SecretPath {
	dir, key := path.Split(fullPath)
	return SecretPath{
		Folder: dir,
		Key:    key,
	}
}

// FullPath returns the complete path including folder and key
func (sp SecretPath) FullPath() string {
	return path.Join(sp.Folder, sp.Key)
}

// SecretEvent represents a secret change event
type SecretEvent struct {
	Secret *Secret
	Action string
}

const (
	// Secret change action types
	SecretActionCreated = "created"
	SecretActionUpdated = "updated"
	SecretActionDeleted = "deleted"
)
