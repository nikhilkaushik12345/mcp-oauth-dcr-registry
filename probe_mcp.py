import subprocess, concurrent.futures, json, sys, os, urllib.request, urllib.error, ssl

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def probe(domain):
    domain = domain.strip()
    if not domain or domain.startswith('#'):
        return None
    mcp_domain = f"mcp.{domain}"
    url = f"https://{mcp_domain}/.well-known/oauth-authorization-server"
    try:
        req = urllib.request.Request(url, method='GET', headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=5, context=ssl_ctx)
        if resp.status == 200:
            body = resp.read().decode('utf-8', errors='replace')
            try:
                data = json.loads(body)
                reg_endpoint = data.get('registration_endpoint', 'N/A')
                auth_endpoint = data.get('authorization_endpoint', 'N/A')
                token_endpoint = data.get('token_endpoint', 'N/A')
                return {
                    'domain': domain,
                    'mcp_domain': mcp_domain,
                    'status': resp.status,
                    'has_registration_endpoint': bool(reg_endpoint and reg_endpoint != 'N/A'),
                    'registration_endpoint': reg_endpoint,
                    'authorization_endpoint': auth_endpoint,
                    'token_endpoint': token_endpoint,
                    'issuer': data.get('issuer', 'N/A'),
                    'response_types_supported': data.get('response_types_supported', []),
                    'code_challenge_methods': data.get('code_challenge_methods_supported', []),
                    'full_body': body[:2000]
                }
            except:
                return {'domain': domain, 'mcp_domain': mcp_domain, 'status': resp.status, 'error': 'parse_error', 'body': body[:500]}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Try /register directly
            try:
                reg_url = f"https://{mcp_domain}/register"
                req2 = urllib.request.Request(reg_url, method='GET', headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
                resp2 = urllib.request.urlopen(req2, timeout=3, context=ssl_ctx)
                if resp2.status == 200:
                    return {'domain': domain, 'mcp_domain': mcp_domain, 'status': f'well-known:404, /register:{resp2.status}', 'direct_register': True, 'body': resp2.read().decode('utf-8', errors='replace')[:500]}
            except:
                pass
            return None
        return None
    except Exception as e:
        return None

# Read domains from file or stdin
if len(sys.argv) > 1:
    domains = open(sys.argv[1]).readlines()
else:
    domains = sys.stdin.readlines()

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(probe, d): d for d in domains}
    for i, future in enumerate(concurrent.futures.as_completed(futures)):
        r = future.result()
        if r:
            results.append(r)
        if (i+1) % 100 == 0:
            print(f"Progress: {i+1}/{len(domains)} checked, {len(results)} found", file=sys.stderr)

print(f"\n=== RESULTS: {len(results)} MCP servers with registration endpoints ===", file=sys.stderr)
print(json.dumps(results, indent=2))
