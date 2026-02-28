// Package web embeds the static UI files.
package web

import "embed"

//go:embed *.html
var Static embed.FS
