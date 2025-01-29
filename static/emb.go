package static

import (
	"embed"
)

//go:embed finger/finger.json poc
var EmbedFS embed.FS
