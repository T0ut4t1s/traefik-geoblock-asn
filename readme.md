# GeoBlock ASN

A [Traefik](https://github.com/traefik/traefik) middleware plugin that blocks or allows requests based on their country of origin and/or ASN (Autonomous System Number). Uses [GeoJS](https://www.geojs.io/) for IP geolocation and ASN lookups.

> **HTTP routers only.** Traefik's plugin system supports HTTP middleware and providers;
> there is no TCP plugin interface, so this plugin cannot be used in `tcp.middlewares`.
> Attempting it fails at config parse time with
> `Error occurred during watcher callback error="field not found, node: plugin"`.
> The TCP middlewares shown in the Traefik dashboard are the built-ins only
> (`ipAllowList`, `inFlightConn`), and that set is not plugin-extensible.

## Features

- **Country filtering**: Allow or block requests by country code (whitelist or blacklist mode)
- **File-based country list**: Load allowed/blocked countries from a JSON file with periodic refresh
- **ASN filtering**: Block or allow requests by ASN number to target specific ISPs, cloud providers, or organizations
- **File-based ASN blocklist**: Load blocked ASNs from a JSON file with periodic refresh — no Traefik restart needed
- **IP allowlisting**: Explicitly allow specific IPs or CIDR ranges
- **Path exclusions**: Bypass geo-blocking for specific URL patterns (health checks, webhooks, etc.)
- **LRU caching**: Minimize API calls with a configurable cache
- **Custom headers**: Add `X-IPCountry` and `X-IPASN` headers to requests

## Installation

### Traefik Plugin Registry

Add to your Traefik static configuration:

```yaml
experimental:
  plugins:
    geoblock:
      moduleName: github.com/T0ut4t1s/traefik-geoblock-asn
      version: v0.6.0
```

### Local Plugin

Download the source and mount it into the Traefik container:

```yaml
volumes:
  - ./plugin/geoblock:/plugins-local/src/github.com/T0ut4t1s/traefik-geoblock-asn/
```

```yaml
experimental:
  localPlugins:
    geoblock:
      moduleName: github.com/T0ut4t1s/traefik-geoblock-asn
```

## Configuration

### Middleware Example

```yaml
http:
  middlewares:
    my-geoblock:
      plugin:
        geoblock:
          # General
          silentStartUp: false
          allowLocalRequests: true
          logLocalRequests: false
          logAllowedRequests: false
          logApiRequests: false

          # Geolocation API
          api: "https://get.geojs.io/v1/ip/geo/{ip}.json"
          apiTimeoutMs: 750
          ignoreApiTimeout: false
          ignoreApiFailures: false

          # Cache
          cacheSize: 25
          forceMonthlyUpdate: true

          # Country filtering
          countries:
            - GB
            - US
          countriesFile: "/data/allowed-countries/allowed-countries.json"
          countriesFileRefreshSecs: 300
          blackListMode: false
          allowUnknownCountries: false
          unknownCountryApiResponse: "nil"
          addCountryHeader: true

          # ASN filtering
          blockedASNs:
            - 16509  # AWS
            - 14061  # DigitalOcean
            - 24940  # Hetzner
          blockedASNsFile: "/data/asn-blocklist/blocked-asns.json"
          blockedASNsFileRefreshSecs: 300
          allowedASNs: []
          allowUnknownAsn: false
          addAsnHeader: true

          # IP allowlist
          allowedIPAddresses:
            - 203.0.113.50
            - 198.51.100.0/24

          # Path exclusions
          excludedPathPatterns:
            - "^[^/]+/health$"
            - "^[^/]+/api/webhook/.*"

          # Response
          httpStatusCodeDeniedRequest: 403
```

### Kubernetes (Traefik CRD)

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: geoblock
spec:
  plugin:
    geoblock:
      silentStartUp: false
      allowLocalRequests: true
      logLocalRequests: false
      logAllowedRequests: false
      logApiRequests: false
      api: "https://get.geojs.io/v1/ip/geo/{ip}.json"
      apiTimeoutMs: 750
      cacheSize: 25
      forceMonthlyUpdate: true
      countries:
        - GB  # fallback if countriesFile not available
      countriesFile: "/data/allowed-countries/allowed-countries.json"
      countriesFileRefreshSecs: 300
      blackListMode: false
      allowUnknownCountries: false
      unknownCountryApiResponse: "nil"
      addCountryHeader: true
      blockedASNsFile: "/data/asn-blocklist/blocked-asns.json"
      blockedASNsFileRefreshSecs: 300
      blockedASNs:
        - 16509  # AWS (fallback if file not available)
      allowedASNs: []
      allowUnknownAsn: false
      addAsnHeader: true
      httpStatusCodeDeniedRequest: 403
```

## Configuration Reference

### General

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `silentStartUp` | bool | `false` | Suppress configuration logging on startup |
| `allowLocalRequests` | bool | `false` | Allow requests from [private IP ranges](https://en.wikipedia.org/wiki/Private_network) |
| `logLocalRequests` | bool | `false` | Log requests from private IP addresses |
| `logAllowedRequests` | bool | `false` | Log allowed requests with IP and country |
| `logApiRequests` | bool | `false` | Log every API lookup |
| `logFilePath` | string | | Path to a custom log file (folder must be writable) |

### Geolocation API

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api` | string | **required** | API URL with `{ip}` placeholder. Use the JSON endpoint for ASN support: `https://get.geojs.io/v1/ip/geo/{ip}.json` |
| `apiTimeoutMs` | int | `750` | API request timeout in milliseconds |
| `ignoreApiTimeout` | bool | `false` | Allow requests when the API times out |
| `ignoreApiFailures` | bool | `false` | Allow requests when the API returns an error |
| `ipGeolocationHttpHeaderField` | string | | Read country code from this HTTP header instead of calling the API (e.g. `cf-ipcountry` for Cloudflare) |
| `xForwardedForReverseProxy` | bool | `false` | Only use the first IP in `X-Forwarded-For` (for services behind a reverse proxy like Cloudflare) |

### Cache

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cacheSize` | int | **required** | Maximum number of entries in the LRU cache |
| `forceMonthlyUpdate` | bool | `false` | Re-fetch cached entries after ~30 days |

### Country Filtering

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `countries` | []string | | List of country codes (ISO 3166-1 alpha-2). Used as fallback when `countriesFile` is not available. Required **unless** an ASN filter (`blockedASNs`, `allowedASNs`, or `blockedASNsFile`) is configured — see [ASN-Only Mode](#asn-only-mode) |
| `countriesFile` | string | | Path to a JSON file containing an array of country code strings (e.g. `["GB", "US"]`). When loaded, overrides `countries` |
| `countriesFileRefreshSecs` | int | `300` | How often (in seconds) to re-read the countries file |
| `blackListMode` | bool | `false` | When `false` (whitelist mode), only listed countries are allowed. When `true` (blacklist mode), listed countries are blocked |
| `allowUnknownCountries` | bool | `false` | Allow requests from IPs with no associated country |
| `unknownCountryApiResponse` | string | | The API response string that indicates an unknown country |
| `addCountryHeader` | bool | `false` | Add `X-IPCountry` header to forwarded requests |

#### File-Based Country List

The `countriesFile` option points to a JSON file containing an array of country code strings:

```json
["GB", "US", "ZA", "JP"]
```

This allows updating the allowed country list without restarting Traefik or modifying the Middleware configuration. The plugin:

1. Reads the file on startup
2. Re-reads it periodically (controlled by `countriesFileRefreshSecs`)
3. Falls back to inline `countries` if the file doesn't exist or is empty
4. Is thread-safe — file reads don't block request processing

### ASN Filtering

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `blockedASNs` | []int | `[]` | ASN numbers to block. Used as fallback when `blockedASNsFile` is not available |
| `blockedASNsFile` | string | | Path to a JSON file containing an array of blocked ASN numbers. When loaded, overrides `blockedASNs` |
| `blockedASNsFileRefreshSecs` | int | `300` | How often (in seconds) to re-read the blocked ASNs file |
| `allowedASNs` | []int | `[]` | ASN numbers to allow (whitelist). When configured, only these ASNs are permitted |
| `allowUnknownAsn` | bool | `false` | Allow requests from IPs with no associated ASN (only applies when `allowedASNs` is configured) |
| `addAsnHeader` | bool | `false` | Add `X-IPASN` header to forwarded requests |

ASN numbers can be looked up at [bgp.he.net](https://bgp.he.net/) or [ipinfo.io](https://ipinfo.io/).

#### File-Based ASN Blocklist

The `blockedASNsFile` option points to a JSON file containing an array of ASN integers:

```json
[16509, 14618, 8075, 396982, 15169, 24940]
```

This allows updating the blocked ASN list without restarting Traefik or modifying the Middleware configuration. The plugin:

1. Reads the file on startup
2. Re-reads it periodically (controlled by `blockedASNsFileRefreshSecs`)
3. Falls back to inline `blockedASNs` if the file doesn't exist or is empty
4. Is thread-safe — file reads don't block request processing

#### ASN-Only Mode

> **Available since v0.6.0.** Earlier versions require a country list and reject an
> ASN-only config at startup with `no allowed country code provided`.

You can run the plugin with **ASN filtering only** and no country list at all. When neither
`countries` nor `countriesFile` is configured, country filtering is skipped entirely and the
allow/deny decision is made purely from the ASN rules. (At least one filter — country *or* ASN —
must still be present, otherwise the plugin refuses to start.)

```yaml
api: "https://get.geojs.io/v1/ip/geo/{ip}.json"  # JSON endpoint required for ASN data
cacheSize: 25
blackListMode: true        # optional; ASN-only works in either mode
blockedASNs:
  - 16509  # AWS
  - 15169  # Google
allowUnknownAsn: true
# no countries / countriesFile
```

In Kubernetes, mount ConfigMaps as **directories** (not `subPath`) so that kubelet can auto-update the files when ConfigMaps change:

```yaml
# Traefik Helm values
deployment:
  additionalVolumes:
    - name: asn-blocklist
      configMap:
        name: asn-blocklist
        optional: true  # Traefik starts even if the ConfigMap doesn't exist yet
    - name: allowed-countries
      configMap:
        name: allowed-countries
        optional: true

additionalVolumeMounts:
  - name: asn-blocklist
    mountPath: /data/asn-blocklist
    readOnly: true
  - name: allowed-countries
    mountPath: /data/allowed-countries
    readOnly: true
```

### IP Allowlist

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowedIPAddresses` | []string | `[]` | IPs or CIDR ranges that are always allowed, bypassing all geo/ASN checks |

```yaml
allowedIPAddresses:
  - 192.0.2.10        # single IPv4
  - 203.0.113.0/24    # IPv4 CIDR range
  - 2001:db8:1234::/48  # IPv6 CIDR range
```

### Path Exclusions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `excludedPathPatterns` | []string | `[]` | Regex patterns for paths that bypass all checks |

Patterns match against `{domain}{path}` (e.g. `example.com/health`):

```yaml
excludedPathPatterns:
  - "^[^/]+/health$"                 # /health on any domain
  - "^[^/]+/api/webhook/.*"          # /api/webhook/* on any domain
  - "^webhook\\.example\\.com"       # Any path on webhook.example.com
```

### Response

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `httpStatusCodeDeniedRequest` | int | `403` | HTTP status code for denied requests |
| `redirectUrlIfDenied` | string | | Redirect denied requests to this URL (HTTP 302) instead of returning the status code |

## Request Evaluation Order

1. **Path exclusions** — if the request URL matches an excluded pattern, it is allowed immediately
2. **Private IPs** — checked against `allowLocalRequests`
3. **IP allowlist** — if the IP matches `allowedIPAddresses`, it is allowed
4. **Country check** — the IP's country is looked up and checked against the `countries` list (respecting `blackListMode`)
5. **ASN block check** — if the IP's ASN is in the effective blocked list (file-based or inline), it is denied
6. **ASN allow check** — if `allowedASNs` is configured, only those ASNs are permitted

## License

[Apache 2.0](LICENSE)
