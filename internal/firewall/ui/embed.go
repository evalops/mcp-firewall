package ui

import (
	"embed"
	"io/fs"
)

//go:embed assets/*
var assets embed.FS

func FS() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		return assets
	}
	return sub
}
