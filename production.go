//go:build !dev
// +build !dev

package main

import (
	"embed"
	"io/fs"
)

//go:embed frontend/dist/*
var embeddedFiles embed.FS

func GetStaticFS() (fs.FS, error) {
	return fs.Sub(embeddedFiles, "frontend/dist")
}
