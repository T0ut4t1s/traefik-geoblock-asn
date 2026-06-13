package traefik_geoblock_asn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	geoblock "github.com/T0ut4t1s/traefik-geoblock-asn"
)

// asnOnlyMockServer is a small helper returning a JSON geo API that maps a single
// IP to a fixed country/ASN, mirroring createJSONMockAPIServer in geoblock_test.go.
func asnOnlyMockServer(t *testing.T, ip, country string, asn int) *httptest.Server {
	t.Helper()
	return createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		ip: {CountryCode: country, ASN: asn},
	})
}

func doRequest(t *testing.T, handler http.Handler, ip string) *http.Response {
	t.Helper()
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add(xForwardedFor, ip)
	handler.ServeHTTP(recorder, req)
	return recorder.Result()
}

// TestASNOnlyStartupNoCountries verifies the plugin starts with ONLY ASN filtering
// configured (no countries, no countriesFile). This is the issue #3 scenario.
func TestASNOnlyStartupNoCountries(t *testing.T) {
	cfg := createTesterConfig()
	cfg.API = apiURIJSON
	cfg.BlackListMode = true
	cfg.BlockedASNs = append(cfg.BlockedASNs, blockedASN)
	// Countries deliberately left empty.

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := geoblock.New(context.Background(), next, cfg, "GeoBlock")
	if err != nil {
		t.Fatalf("ASN-only config should start without a country list, got error: %v", err)
	}
}

// TestASNOnlyBlocksBlockedASN: blacklist ASN-only config denies the blocked ASN.
func TestASNOnlyBlocksBlockedASN(t *testing.T) {
	mockServer := asnOnlyMockServer(t, chExampleIP, "CH", blockedASN)
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.API = mockServer.URL + "/{ip}.json"
	cfg.BlackListMode = true
	cfg.BlockedASNs = append(cfg.BlockedASNs, blockedASN)

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := geoblock.New(context.Background(), next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	assertStatusCode(t, doRequest(t, handler, chExampleIP), http.StatusForbidden)
}

// TestASNOnlyAllowsOtherASN: the critical "don't break ingress" case — an ASN-only
// config must ALLOW traffic from any non-blocked ASN, not deny everything.
func TestASNOnlyAllowsOtherASN(t *testing.T) {
	mockServer := asnOnlyMockServer(t, chExampleIP, "CH", chExampleASN)
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.API = mockServer.URL + "/{ip}.json"
	cfg.BlackListMode = true
	cfg.BlockedASNs = append(cfg.BlockedASNs, blockedASN) // chExampleASN is NOT blocked

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})
	handler, err := geoblock.New(context.Background(), next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	assertStatusCode(t, doRequest(t, handler, chExampleIP), http.StatusOK)
}

// TestASNOnlyAllowlistWhitelistMode: allowlist ASN-only with the DEFAULT country mode
// (BlackListMode=false). Without making the country check a no-op when no countries are
// configured, an empty country list in whitelist mode would deny everyone. This guards
// against the naive "just delete the startup check" fix.
func TestASNOnlyAllowlistWhitelistMode(t *testing.T) {
	mockServer := asnOnlyMockServer(t, chExampleIP, "CH", chExampleASN)
	defer mockServer.Close()

	cfg := createTesterConfig() // BlackListMode defaults to false
	cfg.API = mockServer.URL + "/{ip}.json"
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})
	handler, err := geoblock.New(context.Background(), next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	assertStatusCode(t, doRequest(t, handler, chExampleIP), http.StatusOK)
}

// TestNoFilterStillRejected: with NEITHER a country filter NOR an ASN filter, startup
// must still fail. This preserves the existing safety guarantee (see
// TestEmptyAllowedCountryList) so a misconfigured middleware never silently allows all.
func TestNoFilterStillRejected(t *testing.T) {
	cfg := createTesterConfig()
	cfg.API = apiURIJSON
	// No countries, no countriesFile, no ASN filters.

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := geoblock.New(context.Background(), next, cfg, "GeoBlock")
	if err == nil {
		t.Fatal("config with no country or ASN filter should be rejected")
	}
}
