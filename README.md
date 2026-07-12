# MCP OAuth DCR Registry

Probed **2,524** domains for MCP (Model Context Protocol) OAuth Dynamic Client Registration endpoints.

## Results

| Metric | Count |
|--------|-------|
| Domains scanned | 2,524 |
| Responded with OAuth metadata | 2,081 |
| With registration endpoint | 1,841 |
| DCR clients registered | 1,511 |
| Auth URLs generated (PKCE S256) | 927 |
| Redirect to `mcp.` URIs | 94 |

## Files

- **probe_results.json** — Raw probe output: OAuth metadata for each `mcp.{domain}`
- **dcr_results.json** — First pass DCR registration results
- **dcr_all.json** — Combined DCR results (first pass + retry)
- **auth_urls.json** — Authorization URLs with PKCE code_verifier/challenge for each registered client
- **oauth_endpoints.json** — All preserved OAuth endpoints (auth, token, registration) with client IDs
- **visit_results.json** — Full visit results including redirect chains and `mcp.` URI detection

## Methodology

1. **Probe**: Check `https://mcp.{domain}/.well-known/oauth-authorization-server` on 2,524 domains (50 parallel workers)
2. **DCR Register**: POST to registration_endpoint with `redirect_uris: ["https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1/callback"]` (30 parallel workers)
3. **PKCE Auth URLs**: Generate S256 code_verifier/code_challenge, build authorization URL
4. **Visit**: HTTP GET on each auth URL, capture redirect chain and `mcp.` URI detection
