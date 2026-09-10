package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeCSV(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoad_ParsesCIDRRowsAndLooksUpCorrectly(t *testing.T) {
	path := writeCSV(t, "1.2.3.0/24,US\n5.6.7.0/24,SE\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	country, ok := table.Country(net.ParseIP("1.2.3.42"))
	if !ok || country != "US" {
		t.Fatalf("Country(1.2.3.42) = (%q, %v), want (US, true)", country, ok)
	}
	country, ok = table.Country(net.ParseIP("5.6.7.99"))
	if !ok || country != "SE" {
		t.Fatalf("Country(5.6.7.99) = (%q, %v), want (SE, true)", country, ok)
	}
}

func TestLoad_BareIPNormalizedToSingleHostRange(t *testing.T) {
	path := writeCSV(t, "9.9.9.9,US\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if country, ok := table.Country(net.ParseIP("9.9.9.9")); !ok || country != "US" {
		t.Fatalf("Country(9.9.9.9) = (%q, %v), want (US, true)", country, ok)
	}
	if _, ok := table.Country(net.ParseIP("9.9.9.10")); ok {
		t.Fatal("Country(9.9.9.10) matched a /32 range one address over — should not")
	}
}

func TestLoad_LowercaseCountryCodeNormalizedToUppercase(t *testing.T) {
	path := writeCSV(t, "1.2.3.0/24,us\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if country, _ := table.Country(net.ParseIP("1.2.3.1")); country != "US" {
		t.Fatalf("country = %q, want %q", country, "US")
	}
}

func TestLoad_SkipsCommentsAndBlankLines(t *testing.T) {
	path := writeCSV(t, "# a comment\n\n1.2.3.0/24,US\n\n# another comment\n5.6.7.0/24,SE\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if table.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", table.Len())
	}
}

func TestLoad_InvalidCIDRIsAClearError(t *testing.T) {
	path := writeCSV(t, "not-an-ip,US\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an invalid CIDR/IP, got nil")
	} else if !strings.Contains(err.Error(), "row 1") {
		t.Fatalf("error = %v, want it to mention row 1", err)
	}
}

func TestLoad_InvalidCountryCodeIsAClearError(t *testing.T) {
	for _, bad := range []string{"USA", "U", "12", ""} {
		path := writeCSV(t, "1.2.3.0/24,"+bad+"\n")
		if _, err := Load(path); err == nil {
			t.Fatalf("country code %q: expected an error, got nil", bad)
		}
	}
}

func TestLoad_WrongFieldCountIsAClearError(t *testing.T) {
	path := writeCSV(t, "1.2.3.0/24,US,extra\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a row with the wrong field count, got nil")
	}
}

func TestLoad_MissingFileIsAClearError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.csv")); err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

func TestTable_Country_UnmatchedIPReturnsFalse(t *testing.T) {
	path := writeCSV(t, "1.2.3.0/24,US\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := table.Country(net.ParseIP("8.8.8.8")); ok {
		t.Fatal("Country(8.8.8.8) matched a range it shouldn't have")
	}
}

func TestTable_Country_IPv6RangesLookUpIndependentlyOfIPv4(t *testing.T) {
	path := writeCSV(t, "1.2.3.0/24,US\n2001:db8::/32,SE\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if country, ok := table.Country(net.ParseIP("2001:db8::1")); !ok || country != "SE" {
		t.Fatalf("Country(2001:db8::1) = (%q, %v), want (SE, true)", country, ok)
	}
	if country, ok := table.Country(net.ParseIP("1.2.3.1")); !ok || country != "US" {
		t.Fatalf("Country(1.2.3.1) = (%q, %v), want (US, true)", country, ok)
	}
	if _, ok := table.Country(net.ParseIP("2001:db9::1")); ok {
		t.Fatal("Country(2001:db9::1) unexpectedly matched an IPv6 range outside it")
	}
}

func TestTable_Country_BoundaryAddressesOfAdjacentRangesResolveCorrectly(t *testing.T) {
	path := writeCSV(t, "10.0.0.0/24,US\n10.0.1.0/24,SE\n10.0.2.0/24,NO\n")
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := map[string]string{
		"10.0.0.0":   "US",
		"10.0.0.255": "US",
		"10.0.1.0":   "SE",
		"10.0.1.255": "SE",
		"10.0.2.0":   "NO",
		"10.0.2.255": "NO",
	}
	for ip, want := range cases {
		got, ok := table.Country(net.ParseIP(ip))
		if !ok || got != want {
			t.Errorf("Country(%s) = (%q, %v), want (%q, true)", ip, got, ok, want)
		}
	}
	if _, ok := table.Country(net.ParseIP("10.0.3.0")); ok {
		t.Error("Country(10.0.3.0) matched a range beyond the last one — should not")
	}
	if _, ok := table.Country(net.ParseIP("9.255.255.255")); ok {
		t.Error("Country(9.255.255.255) matched a range before the first one — should not")
	}
}

func TestTable_Len_NilTableReturnsZero(t *testing.T) {
	var table *Table
	if got := table.Len(); got != 0 {
		t.Fatalf("Len() on a nil table = %d, want 0", got)
	}
}

func TestTable_Country_ManyRangesStillFindsCorrectEntry(t *testing.T) {
	var sb strings.Builder
	// 2000 disjoint /24s, each assigned a distinct synthetic country
	// code cycling through a small set — enough entries that a linear
	// scan bug (rather than the intended binary search) would still
	// technically pass, but this at least exercises Load/Country at a
	// scale closer to a real exported dataset than the tiny fixtures
	// above.
	codes := []string{"US", "SE", "NO", "DK", "FI"}
	for i := 0; i < 2000; i++ {
		sb.WriteString("10.")
		sb.WriteString(strconv.Itoa(i / 256))
		sb.WriteString(".")
		sb.WriteString(strconv.Itoa(i % 256))
		sb.WriteString(".0/24,")
		sb.WriteString(codes[i%len(codes)])
		sb.WriteString("\n")
	}
	path := writeCSV(t, sb.String())
	table, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if table.Len() != 2000 {
		t.Fatalf("Len() = %d, want 2000", table.Len())
	}

	// Spot-check a handful of specific entries by their known index.
	for _, i := range []int{0, 1, 500, 1234, 1999} {
		ip := net.ParseIP("10." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ".7")
		want := codes[i%len(codes)]
		got, ok := table.Country(ip)
		if !ok || got != want {
			t.Errorf("Country(%s) [entry %d] = (%q, %v), want (%q, true)", ip, i, got, ok, want)
		}
	}
}
