# GeoBlock ASN Testing

This folder contains manifests for testing the GeoBlock ASN plugin in an isolated environment.

## Files

| File | Description |
|------|-------------|
| `geoblock-test.yaml` | Full deployment: namespace, networkpolicy, nginx, service, middleware, ingressroute |
| `geoblock-test-asn-block.yaml` | Middleware variant with cloud provider ASNs blocked |

## Prerequisites

- Kubernetes cluster with Traefik ingress controller
- GeoBlock ASN plugin installed in Traefik
- DNS record for `geoblock-test.scheeps.online` (or edit the IngressRoute host)
- cert-manager with `letsencrypt` certResolver (or adjust TLS config)

## Quick Start

### 1. Deploy the test stack

```bash
kubectl apply -f geoblock-test.yaml
```

### 2. Add DNS record

Point `geoblock-test.scheeps.online` to your Traefik ingress IP.

Or for local testing, add to `/etc/hosts`:
```
<traefik-ip> geoblock-test.scheeps.online
```

### 3. Test basic access

```bash
curl -v https://geoblock-test.scheeps.online
```

Expected response (if your country is allowed):
```
GeoBlock Test OK

Host: geoblock-test.scheeps.online
Remote Addr: 10.42.x.x
X-Forwarded-For: <your-public-ip>
X-Real-IP: <your-public-ip>
X-IPCountry: GB
X-IPASN: 2856
```

### 4. Test health endpoint (should bypass geoblock)

```bash
curl https://geoblock-test.scheeps.online/health
```

This should always return `healthy` regardless of country/ASN.

### 5. Test ASN blocking

Apply the ASN blocking middleware:

```bash
kubectl apply -f geoblock-test-asn-block.yaml
```

This blocks common cloud providers:
- 14061 - DigitalOcean
- 16509 - Amazon AWS
- 15169 - Google Cloud
- 20473 - Vultr

Test from a VPS on one of these providers - it should be blocked with HTTP 403.

### 6. Check logs

View Traefik logs to see geoblock decisions:

```bash
kubectl -n ingress-system logs -l app.kubernetes.io/name=traefik --tail=100 | grep -i geoblock
```

### 7. Cleanup

```bash
kubectl delete -f geoblock-test.yaml
```

## Testing Scenarios

### Test country blocking

Edit the middleware to remove your country from the allowed list:

```yaml
countries:
  - XX  # Some other country, not yours
```

Apply and verify you get HTTP 403 Forbidden.

### Test ASN whitelist mode

To only allow specific ISPs, use `allowedASNs` instead of `blockedASNs`:

```yaml
allowedASNs:
  - 2856   # BT
  - 5089   # Virgin Media
blockedASNs: []
allowUnknownAsn: false
```

### Test with VPN

1. Connect to a VPN in an allowed country → should work
2. Connect to a VPN in a blocked country → should get 403
3. Connect to a VPN on a blocked ASN (e.g., cloud provider) → should get 403

## Finding ASN Numbers

Look up ASN numbers for ISPs/organizations:

- [bgp.he.net](https://bgp.he.net/) - Search by name or IP
- [ipinfo.io](https://ipinfo.io/) - Shows ASN for your current IP
- [peeringdb.com](https://www.peeringdb.com/) - Detailed peering info

### Common UK ISPs

| ASN | Provider | Type |
|-----|----------|------|
| 2856 | BT | Broadband/Mobile |
| 5089 | Virgin Media | Broadband |
| 6830 | Liberty Global | Broadband (Virgin) |
| 12576 | EE | Mobile/Broadband |
| 5378 | Vodafone UK | Mobile |
| 25135 | Vodafone UK | Mobile (Backbone) |
| 13285 | TalkTalk | Broadband |
| 20712 | Andrews & Arnold | Broadband |

### Common NL ISPs

| ASN | Provider | Type |
|-----|----------|------|
| 1136 | KPN | Broadband/Mobile |
| 15542 | Ziggo | Broadband |
| 3265 | XS4ALL | Broadband |

### Common South Africa ISPs

| ASN | Provider | Type |
|-----|----------|------|
| 37611 | Afrihost | Fibre/Broadband |
| 16637 | MTN SA | Mobile |
| 29975 | Vodacom | Mobile |
| 36994 | Vodacom Business | Business |

### Common US ISPs

| ASN | Provider | Type |
|-----|----------|------|
| 21928 | T-Mobile USA | Mobile |
| 22140 | T-Mobile USA | Mobile (Secondary) |
| 701 | Verizon | Fios/Business |
| 6167 | Verizon | Fios/Cellco |
| 7018 | AT&T | Broadband/Mobile |
| 7922 | Comcast | Broadband |
| 20001 | Charter/Spectrum | Broadband |

### Cloud/VPN Providers (commonly blocked)

| ASN | Provider |
|-----|----------|
| 14061 | DigitalOcean |
| 16509 | Amazon AWS |
| 15169 | Google Cloud |
| 8075 | Microsoft Azure |
| 13335 | Cloudflare |
| 20473 | Vultr |
| 63949 | Linode |
| 24940 | Hetzner |

## Troubleshooting

### Plugin not loading

Check Traefik logs for plugin errors:

```bash
kubectl -n ingress-system logs -l app.kubernetes.io/name=traefik | grep -i plugin
```

### Requests not being filtered

1. Verify the middleware is attached to the IngressRoute
2. Check if `allowLocalRequests: true` is bypassing checks for internal IPs
3. Verify the API endpoint is reachable from Traefik pods

### API timeouts

If GeoJS API is slow, increase `apiTimeoutMs` or set `ignoreAPITimeout: true` to allow requests when API is unavailable.
