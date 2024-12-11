package http

import (
	"context"
	"github.com/polite007/Milkyway/pkg/neutron/commons"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	// @Host:target overrides the input target with the annotated one (similar to self-contained requests)
	reHostAnnotation = regexp.MustCompile(`(?m)^@Host:\s*(.+)\s*$`)
	// @tls-sni:target overrides the input target with the annotated one
	// special values:
	// request.host: takes the value from the host header
	// target: overiddes with the specific value
	//reSniAnnotation = regexp.MustCompile(`(?m)^@tls-sni:\s*(.+)\s*$`)
	// @timeout:duration overrides the input timout with a custom duration
	reTimeoutAnnotation = regexp.MustCompile(`(?m)^@timeout:\s*(.+)\s*$`)
	// @once sets the request to be executed only once for a specific URL
	//reOnceAnnotation = regexp.MustCompile(`(?m)^@once\s*$`)
)

// parseAnnotations and override requests settings
func (r *Request) parseAnnotations(rawRequest string, request *http.Request) (*http.Request, bool) {
	// parse request for known ovverride annotations
	var modified bool
	// @Host:target
	if hosts := reHostAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		value := strings.TrimSpace(hosts[1])
		// handle scheme
		switch {
		case commons.HasPrefixI(value, "http://"):
			request.URL.Scheme = "http"
		case commons.HasPrefixI(value, "https://"):
			request.URL.Scheme = "https"
		}

		value = commons.TrimPrefixAny(value, "http://", "https://")

		//if isHostPort(value) {
		//	request.URL.Host = value
		//} else {
		//	hostPort := value
		//	port := request.URL.Port()
		//	if port != "" {
		//		hostPort = net.JoinHostPort(hostPort, port)
		//	}
		//	request.URL.Host = hostPort
		//}
		hostPort := value
		port := request.URL.Port()
		if port != "" {
			hostPort = net.JoinHostPort(hostPort, port)
		}
		request.URL.Host = hostPort
		modified = true

	}

	// @tls-sni:target
	//if hosts := reSniAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
	//	value := strings.TrimSpace(hosts[1])
	//	value = stringsutil.TrimPrefixAny(value, "http://", "https://")
	//	if idxForwardSlash := strings.Index(value, "/"); idxForwardSlash >= 0 {
	//		value = value[:idxForwardSlash]
	//	}
	//
	//	if stringsutil.EqualFoldAny(value, "request.host") {
	//		value = request.Host
	//	}
	//	ctx := context.WithValue(request.Context(), fastdialer.SniName, value)
	//	request = request.Clone(ctx)
	//	modified = true
	//}

	// @timeout:duration
	if duration := reTimeoutAnnotation.FindStringSubmatch(rawRequest); len(duration) > 0 {
		modified = true

		value := strings.TrimSpace(duration[1])
		if parsed, err := time.ParseDuration(value); err == nil {
			ctx, _ := context.WithTimeout(context.Background(), parsed)
			request = request.WithContext(ctx)
		} else {
			request = request.WithContext(request.Context())
		}
	}
	return request, modified
}
