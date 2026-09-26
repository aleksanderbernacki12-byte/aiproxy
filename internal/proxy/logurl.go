package proxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// logSafeURL returns u in a form that is safe to write to any log line,
// webhook payload, or Secure Vault evidence record: userinfo and fragment
// removed, every query value replaced with REDACTED (keys kept, since a
// denylist of parameter names misses credentials under unexpected names),
// and the path passed through the configured secret patterns. Policy code
// must keep using the raw URL.
func (s *Server) logSafeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	masked := *u
	masked.User = nil
	masked.Fragment = ""
	masked.RawFragment = ""
	masked.RawQuery = maskQueryValues(u.RawQuery)
	// Mask the escaped form, since that is what String prints; RawPath
	// keeps the placeholder's brackets from being percent-encoded.
	masked.RawPath = s.getEngine().MaskSecrets(u.EscapedPath())
	// Path must never keep the unmasked original: String falls back to it
	// whenever RawPath is not a valid encoding of it.
	unescaped, err := url.PathUnescape(masked.RawPath)
	if err != nil {
		unescaped = masked.RawPath
	}
	masked.Path = unescaped
	return masked.String()
}

// logSafeRawURL is logSafeURL for a URL held as a string, such as a
// configured target or a *url.Error's URL.
func (s *Server) logSafeRawURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable URL]"
	}
	return s.logSafeURL(u)
}

// logSafeError renders err for a log line. A *url.Error, which every
// http.Client and RoundTrip failure returns, prints its full request URL
// including the query, so its URL is masked.
func (s *Server) logSafeError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Sprintf("%s %s: %v", urlErr.Op, s.logSafeRawURL(urlErr.URL), urlErr.Err)
	}
	return err.Error()
}

// maskQueryValues works on the raw query so key order, repeated keys and
// the keys' own encoding survive exactly.
func maskQueryValues(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	for index, part := range parts {
		if key, value, _ := strings.Cut(part, "="); value != "" {
			parts[index] = key + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}
