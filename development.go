//go:build dev
// +build dev

package main

import (
	"errors"
	"io/fs"
)

// GetStaticFS returns nil in development mode
func GetStaticFS() (fs.FS, error) {
	return nil, errors.New("static files not available in dev mode")
}
