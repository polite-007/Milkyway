package webfinger

import (
	"github.com/polite007/Milkyway/common/http_custom"
	"github.com/polite007/Milkyway/pkg/utils"
	"github.com/polite007/Milkyway/static"
	"strings"
)

func WebFinger(resp *http_custom.Resps) (string, []string) {
	static.Once.Do(static.InitFingerFile)
	headers := utils.MapToJson(resp.Header)
	var cms []string
	var tags []string
	for _, finp := range static.Assets.Fingerprint {
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
