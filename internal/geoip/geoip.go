// Package geoip loads a simple, provider-agnostic IP-range-to-country
// CSV file and answers fast country lookups for an IP address. It has
// no dependency on the proxy package; proxy.Server wires a Table into
// its own access-control path.
//
// aiproxy defines its own minimal CSV format here rather than parsing
// MaxMind's proprietary .mmdb binary format (or its multi-file CSV
// export, which requires joining a Blocks file against a Locations
// file by geoname_id) — keeping this feature usable with any
// IP-to-country data source, hand-maintained or derived from MaxMind's
// own free export with a short join, and keeping the project's
// stdlib-only, zero-external-dependency discipline intact.
package geoip

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

type entry struct {
	network *net.IPNet
	country string
}

// Table is a loaded set of IP-range-to-country-code assignments. IPv4
// and IPv6 ranges are kept in separate slices, each sorted by the
// range's own start address, so Country can binary-search rather than
// scan linearly — a realistic exported GeoIP dataset commonly runs
// into the hundreds of thousands of ranges, where a linear scan on
// every request would be a real added cost.
type Table struct {
	v4 []entry
	v6 []entry
}

// Load reads a GeoIP ranges CSV file: one "cidr_or_ip,country_code"
// pair per line (a bare IP is normalized to a /32 or /128, the same
// convention the cli package's ip_allow_list/ip_deny_list parsing
// uses). Lines starting with "#" and blank lines are ignored. Ranges
// are assumed non-overlapping, as any legitimate IP-to-country
// assignment is — Country's binary search relies on that.
func Load(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip_ranges_file: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comment = '#'
	r.FieldsPerRecord = 2
	r.TrimLeadingSpace = true

	t := &Table{}
	row := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("geoip_ranges_file: %s: %w", path, err)
		}
		row++

		network, err := parseCIDROrIP(rec[0])
		if err != nil {
			return nil, fmt.Errorf("geoip_ranges_file: %s: row %d: %w", path, row, err)
		}
		country := strings.ToUpper(strings.TrimSpace(rec[1]))
		if !ValidCountryCode(country) {
			return nil, fmt.Errorf("geoip_ranges_file: %s: row %d: %q is not a 2-letter country code", path, row, rec[1])
		}

		e := entry{network: network, country: country}
		if network.IP.To4() != nil {
			t.v4 = append(t.v4, e)
		} else {
			t.v6 = append(t.v6, e)
		}
	}

	sort.Slice(t.v4, func(i, j int) bool { return bytes.Compare(t.v4[i].network.IP, t.v4[j].network.IP) < 0 })
	sort.Slice(t.v6, func(i, j int) bool { return bytes.Compare(t.v6[i].network.IP, t.v6[j].network.IP) < 0 })
	return t, nil
}

func parseCIDROrIP(raw string) (*net.IPNet, error) {
	cidr := raw
	if !strings.Contains(raw, "/") {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("%q is not a valid IP address or CIDR range", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		cidr = fmt.Sprintf("%s/%d", raw, bits)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid IP address or CIDR range", raw)
	}
	return network, nil
}

// ValidCountryCode reports whether s is exactly 2 uppercase ASCII
// letters — the shape of an ISO 3166-1 alpha-2 country code. Exported
// so the cli package's own country_allow_list/country_deny_list
// validation (aiproxy validate, buildLiveConfig) can apply the exact
// same rule Load already enforces on the CSV's own country column,
// without duplicating the check.
func ValidCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// Country returns the country code assigned to ip's containing range,
// or ("", false) if ip isn't covered by any range in the table.
func (t *Table) Country(ip net.IP) (string, bool) {
	var entries []entry
	var key net.IP
	if v4 := ip.To4(); v4 != nil {
		entries, key = t.v4, v4
	} else {
		v6 := ip.To16()
		if v6 == nil {
			return "", false
		}
		entries, key = t.v6, v6
	}

	idx := sort.Search(len(entries), func(i int) bool {
		return bytes.Compare(entries[i].network.IP, key) > 0
	})
	if idx == 0 {
		return "", false
	}
	candidate := entries[idx-1]
	if candidate.network.Contains(ip) {
		return candidate.country, true
	}
	return "", false
}

// Len returns the total number of ranges loaded — nil-safe so a
// not-configured *Table (nil) reports 0 without a caller needing its
// own nil check first, for startup/validate summaries.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.v4) + len(t.v6)
}
