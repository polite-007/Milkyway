package static

import (
	"embed"
)

//go:embed finger/finger_new.json poc_all dict
var EmbedFS embed.FS

// 误报的poc
// CVE-2021-28164
// druid-default-login
// CNVD-C-2023-76801
// CVE-2020-10189
