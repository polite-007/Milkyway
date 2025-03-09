package static

import (
	"embed"
)

//go:embed finger/finger_new.json poc_all
var EmbedFS embed.FS
