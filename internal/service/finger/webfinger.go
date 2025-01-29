package finger

import (
	"github.com/polite007/Milkyway/internal/service/httpx"
	"github.com/polite007/Milkyway/internal/service/initpak"
	"github.com/polite007/Milkyway/internal/utils"
	"strings"
)

func WebFinger(resp *httpx.Resps) (string, []string) {
	initpak.Once.Do(initpak.InitFingerFile)
	headers := utils.MapToJson(resp.Header)
	var cms []string
	var tags []string
	for _, finp := range initpak.Assets.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if utils.IsKeyword(resp.Body, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "faviconhash" {
				if resp.FavHash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if utils.IsRegular(resp.Body, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if utils.IsKeyword(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if utils.IsRegular(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if utils.IsKeyword(resp.Title, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
			if finp.Method == "regular" {
				if utils.IsRegular(resp.Title, finp.Keyword) {
					cms = append(cms, finp.Cms)
					tags = append(tags, finp.Tag...)
				}
			}
		}
	}
	if len(cms) == 0 {
		return "", nil
	}
	cms = utils.RemoveDuplicateSliceString(cms)
	tags = utils.RemoveDuplicateSliceString(tags)
	return strings.Join(cms, "|"), tags
}
