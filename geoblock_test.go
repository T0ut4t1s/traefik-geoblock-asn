package traefik_geoblock_asn_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	geoblock "github.com/T0ut4t1s/traefik-geoblock-asn"
)

const (
	xForwardedFor                = "X-Forwarded-For"
	CountryHeader                = "X-IPCountry"
	ASNHeader                    = "X-IPASN"
	caExampleIP                  = "99.220.109.148"
	chExampleIP                  = "82.220.110.18"
	multiForwardedIP             = "82.220.110.18,192.168.1.1,10.0.0.1"
	multiForwardedIPwithSpaces   = "82.220.110.18, 192.168.1.1, 10.0.0.1"
	privateRangeIP               = "192.168.1.1"
	invalidIP                    = "192.168.1.X"
	unknownCountry               = "1.1.1.1"
	apiURI                       = "https://get.geojs.io/v1/ip/country/{ip}"
	apiURIJSON                   = "https://get.geojs.io/v1/ip/geo/{ip}.json"
	ipGeolocationHTTPHeaderField = "cf-ipcountry"
	allowedRequest               = "Allowed request"
	// Example ASNs for testing
	caExampleASN = 577   // Bell Canada
	chExampleASN = 3303  // Swisscom
	blockedASN   = 15169 // Google
)

func TestEmptyApi(t *testing.T) {
	cfg := createTesterConfig()
	cfg.API = ""
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	// expect error
	if err == nil {
		t.Fatal("empty API uri accepted")
	}
}

func TestMissingIpInApi(t *testing.T) {
	cfg := createTesterConfig()
	cfg.API = "https://get.geojs.io/v1/ip/country/"
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	// expect error
	if err == nil {
		t.Fatal("missing IP block in API uri")
	}
}

func TestEmptyAllowedCountryList(t *testing.T) {
	cfg := createTesterConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	// expect error
	if err == nil {
		t.Fatal("empty country list is not allowed")
	}
}

func TestEmptyDeniedRequestStatusCode(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	if err != nil {
		t.Fatal("no error expected for empty denied request status code")
	}
}

func TestInvalidDeniedRequestStatusCode(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.HTTPStatusCodeDeniedRequest = 1

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	// expect error
	if err == nil {
		t.Fatal("invalid denied request status code supplied")
	}
}

func TestAllowedCountry(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("Allowed request")) })

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusOK)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := allowedRequest
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestMultipleAllowedCountry(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH", "CA")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestMultipleForwardedForIP(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowLocalRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("Allowed request")) })

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, multiForwardedIP)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusOK)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := allowedRequest
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestMultipleForwardedForIPwithSpaces(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowLocalRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("Allowed request")) })

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, multiForwardedIPwithSpaces)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusOK)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := allowedRequest
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func createMockAPIServer(t *testing.T, ipResponseMap map[string][]byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Logf("Intercepted request: %s %s", req.Method, req.URL.String())
		t.Logf("Headers: %v", req.Header)

		requestedIP := req.URL.String()[1:]

		if response, exists := ipResponseMap[requestedIP]; exists {
			t.Logf("Matched IP: %s", requestedIP)
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write(response)
		} else {
			t.Errorf("Unexpected IP: %s", requestedIP)
			rw.WriteHeader(http.StatusNotFound)
			_, _ = rw.Write([]byte(`{"error": "IP not found"}`))
		}
	}))
}

func TestMultipleIpAddresses(t *testing.T) {
	mockServer := createMockAPIServer(t, map[string][]byte{caExampleIP: []byte(`CA`), chExampleIP: []byte(`CH`)})
	defer mockServer.Close()

	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CH")
	cfg.API = mockServer.URL + "/{ip}"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, strings.Join([]string{chExampleIP, caExampleIP}, ","))

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestIpAddressesWithSpaces(t *testing.T) {
	mockServer := createMockAPIServer(t, map[string][]byte{caExampleIP: []byte(`CA`), chExampleIP: []byte(`CH`)})
	defer mockServer.Close()

	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CH")
	cfg.API = mockServer.URL + "/{ip}"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, strings.Join([]string{chExampleIP + " "}, ","))

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestMultipleIpAddressesReverse(t *testing.T) {
	mockServer := createMockAPIServer(t, map[string][]byte{caExampleIP: []byte(`CA`), chExampleIP: []byte(`CH`)})
	defer mockServer.Close()

	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CH")
	cfg.API = mockServer.URL + "/{ip}"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, strings.Join([]string{caExampleIP, chExampleIP}, ","))

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestMultipleIpAddressesProxy(t *testing.T) {
	mockServer := createMockAPIServer(t, map[string][]byte{caExampleIP: []byte(`CA`)})
	defer mockServer.Close()

	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CA")
	cfg.XForwardedForReverseProxy = true
	cfg.API = mockServer.URL + "/{ip}"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, strings.Join([]string{caExampleIP, chExampleIP}, ","))

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestMultipleIpAddressesProxyReverse(t *testing.T) {
	mockServer := createMockAPIServer(t, map[string][]byte{chExampleIP: []byte(`CH`)})
	defer mockServer.Close()

	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CA")
	cfg.XForwardedForReverseProxy = true
	cfg.API = mockServer.URL + "/{ip}"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, strings.Join([]string{chExampleIP, caExampleIP}, ","))

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestAllowedUnknownCountry(t *testing.T) {
	cfg := createTesterConfig()

	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowUnknownCountries = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, unknownCountry)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestDenyUnknownCountry(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, unknownCountry)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestAllowedCountryCacheLookUp(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Add(xForwardedFor, chExampleIP)

		handler.ServeHTTP(recorder, req)

		assertStatusCode(t, recorder.Result(), http.StatusOK)
	}
}

func TestDeniedCountry(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("Allowed request")) })

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusForbidden)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := ""
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestDeniedCountryWithRedirect(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.RedirectURLIfDenied = "https://google.com"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	result := recorder.Result()
	assertStatusCode(t, result, http.StatusFound)
	assertResponseHeader(t, result, "Location", cfg.RedirectURLIfDenied)
}

func TestCustomDeniedRequestStatusCode(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.HTTPStatusCodeDeniedRequest = 418

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusTeapot)
}

func TestAllowBlacklistMode(t *testing.T) {
	cfg := createTesterConfig()
	cfg.BlackListMode = true
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestDenyBlacklistMode(t *testing.T) {
	cfg := createTesterConfig()
	cfg.BlackListMode = true
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestAllowLocalIP(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowLocalRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, privateRangeIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestPrivateIPRange(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, privateRangeIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestInvalidIp(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, invalidIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestInvalidApiResponse(t *testing.T) {
	// set up our fake api server
	var apiStub = httptest.NewServer(http.HandlerFunc(apiHandlerInvalid))

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// the country is allowed, but the api response is faulty.
	// therefore the request should be blocked
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestApiResponseTimeoutAllowed(t *testing.T) {
	// set up our fake api server
	var apiStub = httptest.NewServer(http.HandlerFunc(apiTimeout))

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.APITimeoutMs = 5
	cfg.IgnoreAPITimeout = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// the country is allowed, but the api response is faulty.
	// therefore the request should be blocked
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestApiResponseTimeoutNotAllowed(t *testing.T) {
	// set up our fake api server
	var apiStub = httptest.NewServer(http.HandlerFunc(apiTimeout))

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.APITimeoutMs = 5
	cfg.IgnoreAPITimeout = false

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// the country is allowed, but the api response is faulty.
	// therefore the request should be blocked
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestExplicitlyAllowedIP(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, caExampleIP)
	cfg.LogLocalRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestExplicitlyAllowedIPWithIPCountryHeader(t *testing.T) {
	// set up our fake api server
	apiHandler := &CountryCodeHandler{ResponseCountryCode: "CA"}
	var apiStub = httptest.NewServer(apiHandler)

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, caExampleIP)
	cfg.LogLocalRequests = true
	cfg.AddCountryHeader = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
	assertRequestHeader(t, req, CountryHeader, "CA")
}

func TestExplicitlyAllowedIPNoMatch(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, caExampleIP)

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestExplicitlyAllowedIPRangeIPV6(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "2a00:00c0:2:3::567:8001/128")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "8.8.8.8")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, "2a00:00c0:2:3::567:8001")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestExplicitlyAllowedIPRangeIPV6NoMatch(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "2a00:00c0:2:3::567:8001/128")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "8.8.8.8")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, "2a00:00c0:2:3::567:8002")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestExplicitlyAllowedIPRangeIPV4(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "178.90.234.0/27")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "8.8.8.8")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, "178.90.234.30")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestExplicitlyAllowedIPRangeIPV4NoMatch(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "178.90.234.0/27")
	cfg.AllowedIPAddresses = append(cfg.AllowedIPAddresses, "8.8.8.8")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, "178.90.234.55")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestCountryHeader(t *testing.T) {
	cfg := createTesterConfig()
	cfg.AddCountryHeader = true
	cfg.Countries = append(cfg.Countries, "CA")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertRequestHeader(t, req, CountryHeader, "CA")
}

func TestIpGeolocationHttpField(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.AddCountryHeader = true
	cfg.IPGeolocationHTTPHeaderField = ipGeolocationHTTPHeaderField

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// we only want to listen to the ipGeolocationHTTPHeader field,
	// therefore we just give another countries IP address to test it.
	req.Header.Add(xForwardedFor, chExampleIP)
	req.Header.Add(ipGeolocationHTTPHeaderField, "CA")

	handler.ServeHTTP(recorder, req)

	assertRequestHeader(t, req, CountryHeader, "CA")
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestIpGeolocationHttpFieldContentInvalid(t *testing.T) {
	apiHandler := &CountryCodeHandler{ResponseCountryCode: "CA"}

	// set up our fake api server
	var apiStub = httptest.NewServer(apiHandler)

	tempDir, err := os.MkdirTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.IPGeolocationHTTPHeaderField = ipGeolocationHTTPHeaderField
	cfg.LogFilePath = tempDir + "/info.log"
	cfg.LogAllowedRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)

	content, err := os.ReadFile(cfg.LogFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("Empty custom log file.")
	}
}

func TestCustomLogFile(t *testing.T) {
	apiHandler := &CountryCodeHandler{ResponseCountryCode: "CA"}

	// set up our fake api server
	var apiStub = httptest.NewServer(apiHandler)

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CA")
	cfg.IPGeolocationHTTPHeaderField = ipGeolocationHTTPHeaderField

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)
	req.Header.Add(ipGeolocationHTTPHeaderField, "")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestLogDeniedDueToHeaderError_FirstCall(t *testing.T) {
	apiHandler := &CountryCodeHandler{ResponseCountryCode: "CA"}

	// set up our fake api server
	var apiStub = httptest.NewServer(apiHandler)

	tempDir, err := os.MkdirTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.IPGeolocationHTTPHeaderField = ipGeolocationHTTPHeaderField
	cfg.LogFilePath = tempDir + "/info.log"
	cfg.LogAllowedRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)
	req.Header.Set(cfg.IPGeolocationHTTPHeaderField, "C")

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)

	content, err := os.ReadFile(cfg.LogFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	wrongCountryCode := "Failed to read country from HTTP header field [cf-ipcountry], continuing with API lookup"
	countryNotAllowed := "request denied [82.220.110.18] for country [CA] ASN ["

	if len(content) == 0 ||
		!strings.Contains(string(content), wrongCountryCode) ||
		!strings.Contains(string(content), countryNotAllowed) {
		t.Fatalf("Empty custom log file or missing expected log lines.")
	}
}

func TestTimeoutOnApiResponse_DenyWhenIgnoreTimeoutFalse(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logtest")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Stub server that responds too slowly for our client timeout.
	apiStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond) // > APITimeoutMs below
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("CH"))
	}))
	defer apiStub.Close()

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.APITimeoutMs = 5         // 5ms client timeout
	cfg.IgnoreAPITimeout = false // timeouts should DENY
	cfg.LogFilePath = tempDir + "/info.log"
	cfg.LogAllowedRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(rec, req)

	assertStatusCode(t, rec.Result(), http.StatusForbidden)

	content, err := os.ReadFile(cfg.LogFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	timeoutError := "context deadline exceeded"

	if len(content) == 0 || !strings.Contains(string(content), timeoutError) {
		t.Fatalf("Empty custom log file or missing expected log lines.")
	}
}

func TestTimeoutOnApiResponse_AllowWhenIgnoreTimeoutTrue(t *testing.T) {
	// Stub server that responds too slowly for our client timeout.
	apiStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond) // > APITimeoutMs below
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("CH"))
	}))
	defer apiStub.Close()

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.APITimeoutMs = 5        // 5ms client timeout
	cfg.IgnoreAPITimeout = true // timeouts should ALLOW

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(rec, req)

	assertStatusCode(t, rec.Result(), http.StatusOK)
}

func TestErrorOnApiResponse_AllowWhenIgnoreAPIFailuresTrue(t *testing.T) {
	// Stub server that fails to respond correctly.
	apiStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiStub.Close()

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.IgnoreAPIFailures = true // API failures should ALLOW

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(rec, req)

	assertStatusCode(t, rec.Result(), http.StatusOK)
}

func TestErrorOnApiResponse_AllowWhenIgnoreAPIFailuresFalse(t *testing.T) {
	// Stub server that fails to respond correctly.
	apiStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiStub.Close()

	cfg := createTesterConfig()
	cfg.API = apiStub.URL + "/{ip}"
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.IgnoreAPIFailures = false // API failures should DENY

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(rec, req)

	assertStatusCode(t, rec.Result(), http.StatusForbidden)
}

func assertStatusCode(t *testing.T, req *http.Response, expected int) {
	t.Helper()

	if received := req.StatusCode; received != expected {
		t.Errorf("invalid status code: %d <> %d", expected, received)
	}
}

func assertRequestHeader(t *testing.T, req *http.Request, key string, expected string) {
	t.Helper()

	if received := req.Header.Get(key); received != expected {
		t.Errorf("header value mismatch: %s: %s <> %s", key, expected, received)
	}
}

func assertResponseHeader(t *testing.T, response *http.Response, key string, expected string) {
	t.Helper()

	if received := response.Header.Get(key); received != expected {
		t.Errorf("header value mismatch: %s: %s <> %s", key, expected, received)
	}
}

type CountryCodeHandler struct {
	ResponseCountryCode string
}

func (h *CountryCodeHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)

	_, err := w.Write([]byte(h.ResponseCountryCode))
	if err != nil {
		fmt.Println("Error on write")
	}
}

func apiHandlerInvalid(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Invalid Response")
}

func apiTimeout(w http.ResponseWriter, _ *http.Request) {
	// Add waiting time for response
	time.Sleep(20 * time.Millisecond)

	w.WriteHeader(http.StatusOK)

	_, err := w.Write([]byte(""))
	if err != nil {
		fmt.Println("Error on write")
	}
}

func TestExcludedPathPattern(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^[^/]+/health$")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusOK)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := allowedRequest
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestExcludedDomainPattern(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^webhook\\.example\\.com")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://webhook.example.com/github", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	recorderResult := recorder.Result()

	assertStatusCode(t, recorderResult, http.StatusOK)

	body, err := io.ReadAll(recorderResult.Body)
	if err != nil {
		t.Fatal(err)
	}

	expectedBody := allowedRequest
	if string(body) != expectedBody {
		t.Fatalf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestExcludedDomainAndPathPattern(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^webhook\\.example\\.com/github$")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://webhook.example.com/github", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestExcludedDomainAndPathPatternNoMatch(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^webhook\\.example\\.com/github$")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://webhook.example.com/stripe", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestExcludedPathPatternMultiple(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^[^/]+/health$", "^[^/]+/status$", "^[^/]+/api/webhook/.*")

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{"/health", "/status", "/api/webhook/github", "/api/webhook/stripe"}

	for _, path := range tests {
		recorder := httptest.NewRecorder()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Add(xForwardedFor, caExampleIP)

		handler.ServeHTTP(recorder, req)

		assertStatusCode(t, recorder.Result(), http.StatusOK)
	}
}

func TestExcludedPathPatternNoMatch(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "^[^/]+/health$")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestInvalidExcludedPathPattern(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.ExcludedPathPatterns = append(cfg.ExcludedPathPatterns, "[invalid")

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := geoblock.New(ctx, next, cfg, "GeoBlock")

	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func createTesterConfig() *geoblock.Config {
	cfg := geoblock.CreateConfig()

	cfg.API = apiURI
	cfg.APITimeoutMs = 750
	cfg.AllowLocalRequests = false
	cfg.AllowUnknownCountries = false
	cfg.CacheSize = 10
	cfg.Countries = make([]string, 0)
	cfg.ForceMonthlyUpdate = true
	cfg.LogAPIRequests = false
	cfg.LogAllowedRequests = false
	cfg.LogLocalRequests = false
	cfg.UnknownCountryAPIResponse = "nil"

	return cfg
}

// JSON mock API server for ASN tests
func createJSONMockAPIServer(t *testing.T, ipResponseMap map[string]struct {
	CountryCode string
	ASN         int
}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Logf("Intercepted request: %s %s", req.Method, req.URL.String())

		// Extract IP from URL path (e.g., /8.8.8.8.json -> 8.8.8.8)
		path := req.URL.Path
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimSuffix(path, ".json")

		if response, exists := ipResponseMap[path]; exists {
			t.Logf("Matched IP: %s", path)
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			jsonResponse := fmt.Sprintf(`{"ip":"%s","country_code":"%s","asn":%d,"organization_name":"Test Org"}`,
				path, response.CountryCode, response.ASN)
			_, _ = rw.Write([]byte(jsonResponse))
		} else {
			t.Errorf("Unexpected IP: %s", path)
			rw.WriteHeader(http.StatusNotFound)
			_, _ = rw.Write([]byte(`{"error": "IP not found"}`))
		}
	}))
}

// ASN Tests

func TestAllowedCountryAllowedASN(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: chExampleASN},
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN)
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestAllowedCountryBlockedASN(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: blockedASN},
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.BlockedASNs = append(cfg.BlockedASNs, blockedASN)
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestAllowedCountryASNNotInAllowlist(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: 99999}, // Some random ASN not in allowlist
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN) // Only allow chExampleASN
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be blocked because ASN is not in the allowed list
	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestAllowedCountryNoASNFiltering(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: blockedASN},
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	// No ASN filtering configured (empty AllowedASNs and BlockedASNs)
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be allowed because no ASN filtering is configured
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestBlockedCountryIgnoresASN(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		caExampleIP: {CountryCode: "CA", ASN: caExampleASN},
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH") // Only CH allowed
	cfg.AllowedASNs = append(cfg.AllowedASNs, caExampleASN)
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, caExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be blocked because country is not allowed (ASN doesn't matter)
	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestLocalIPBypassesASNFiltering(t *testing.T) {
	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN)
	cfg.AllowLocalRequests = true

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, privateRangeIP)

	handler.ServeHTTP(recorder, req)

	// Local IPs should be allowed regardless of ASN filtering
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestASNHeader(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: chExampleASN},
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AddASNHeader = true
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	assertStatusCode(t, recorder.Result(), http.StatusOK)
	assertRequestHeader(t, req, ASNHeader, fmt.Sprintf("%d", chExampleASN))
}

func TestUnknownASNDenied(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: 0}, // Unknown ASN
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN)
	cfg.AllowUnknownASN = false
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be blocked because ASN is unknown and not allowed
	assertStatusCode(t, recorder.Result(), http.StatusForbidden)
}

func TestUnknownASNAllowed(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: 0}, // Unknown ASN
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN)
	cfg.AllowUnknownASN = true
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be allowed because unknown ASN is allowed
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestMultipleAllowedASNs(t *testing.T) {
	mockServer := createJSONMockAPIServer(t, map[string]struct {
		CountryCode string
		ASN         int
	}{
		chExampleIP: {CountryCode: "CH", ASN: caExampleASN}, // Using CA's ASN with CH country
	})
	defer mockServer.Close()

	cfg := createTesterConfig()
	cfg.Countries = append(cfg.Countries, "CH")
	cfg.AllowedASNs = append(cfg.AllowedASNs, chExampleASN, caExampleASN, 12345)
	cfg.API = mockServer.URL + "/{ip}.json"

	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(allowedRequest))
	})

	handler, err := geoblock.New(ctx, next, cfg, "GeoBlock")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add(xForwardedFor, chExampleIP)

	handler.ServeHTTP(recorder, req)

	// Should be allowed because caExampleASN is in the allowed list
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}
