//go:build !dev
// +build !dev

package main

import (
	"embed"
	"io/fs"
)

//go:embed frontend/build/*
var embeddedFiles embed.FS

func GetStaticFS() (fs.FS, error) {
	return fs.Sub(embeddedFiles, "frontend/build")
}
