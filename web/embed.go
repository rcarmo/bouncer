// Package web embeds the static UI files.
package web

import "embed"

//go:embed *.html *.png
var Static embed.FS
