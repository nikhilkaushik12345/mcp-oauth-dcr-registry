import json, concurrent.futures, hashlib, base64, os, urllib.request, urllib.error, urllib.parse, ssl, sys, time, uuid

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

REDIRECT_URI_PRIMARY = "https://claude.ai/api/mcp/auth_callback"
REDIRECT_URI_FALLBACK = "http://127.0.0.1/callback"
AUTH_CALLBACK_URI = "https://claude.ai/api/mcp/auth_callback"

def generate_pkce():
    """Generate S256 PKCE code_verifier and code_challenge"""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge

def register_dcr(server):
    """Register a DCR client and generate authorization URL"""
    domain = server.get('domain', '')
    reg_endpoint = server.get('registration_endpoint', '')
    auth_endpoint = server.get('authorization_endpoint', '')
    token_endpoint = server.get('token_endpoint', '')
    challenges = server.get('code_challenge_methods', [])
    
    if not reg_endpoint or reg_endpoint == 'N/A':
        return None
    
    client_name = f"mcp-client-{domain.replace('.', '-')[:40]}"
    client_body = json.dumps({
        "redirect_uris": [REDIRECT_URI_PRIMARY, REDIRECT_URI_FALLBACK],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
        "client_name": client_name,
        "scope": "mcp:read mcp:tools"
    }).encode('utf-8')
    
    code_verifier, code_challenge = generate_pkce()
    
    try:
        req = urllib.request.Request(reg_endpoint, data=client_body,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            method='POST')
        resp = urllib.request.urlopen(req, timeout=10, context=ssl_ctx)
        body = resp.read().decode('utf-8', errors='replace')
        reg_data = json.loads(body)
        
        client_id = reg_data.get('client_id', '')
        if not client_id:
            return None
        
        # Build authorization URL with PKCE
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': REDIRECT_URI_PRIMARY,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'scope': 'mcp:read mcp:tools',
            'state': uuid.uuid4().hex[:16]
        }
        auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}" if auth_endpoint and auth_endpoint != 'N/A' else None
        
        return {
            'domain': domain,
            'client_id': client_id,
            'client_secret': reg_data.get('client_secret', ''),
            'client_id_issued_at': reg_data.get('client_id_issued_at', ''),
            'registration_access_token': reg_data.get('registration_access_token', ''),
            'code_verifier': code_verifier,
            'code_challenge': code_challenge,
            'authorization_url': auth_url,
            'authorization_endpoint': auth_endpoint if auth_endpoint != 'N/A' else None,
            'token_endpoint': token_endpoint if token_endpoint != 'N/A' else None,
            'registration_endpoint': reg_endpoint,
            'scopes': reg_data.get('scope', ''),
            'raw_response': body[:500]
        }
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8', errors='replace')[:300]
        except:
            err_body = str(e)
        return {'domain': domain, 'error': f'HTTP {e.code}', 'error_body': err_body, 'registration_endpoint': reg_endpoint}
    except Exception as e:
        return {'domain': domain, 'error': str(e)[:200], 'registration_endpoint': reg_endpoint}

def main():
    with open('/home/user/probe_results.json') as f:
        all_servers = json.load(f)
    
    # Filter only servers with registration endpoints
    servers = [s for s in all_servers if s.get('has_registration_endpoint')]
    print(f"Total servers: {len(all_servers)}, with registration endpoints: {len(servers)}", file=sys.stderr)
    
    results = []
    errors = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(register_dcr, s): s for s in servers}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                if 'error' in result:
                    errors.append(result)
                else:
                    results.append(result)
            completed += 1
            if completed % 200 == 0:
                print(f"Progress: {completed}/{len(servers)} DCR registered, {len(results)} success, {len(errors)} errors", file=sys.stderr)
    
    output = {
        'total_servers': len(servers),
        'registered_success': len(results),
        'registration_errors': len(errors),
        'successful_registrations': results,
        'errors': errors
    }
    
    with open('/home/user/dcr_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(json.dumps({
        'total': len(servers),
        'registered': len(results),
        'errors': len(errors)
    }))
    
    # Also output authorization URLs separately
    auth_urls = [r for r in results if r.get('authorization_url')]
    with open('/home/user/auth_urls.json', 'w') as f:
        json.dump([{
            'domain': r['domain'],
            'authorization_url': r['authorization_url'],
            'authorization_endpoint': r['authorization_endpoint'],
            'token_endpoint': r['token_endpoint'],
            'client_id': r['client_id'],
            'code_verifier': r['code_verifier'],
            'code_challenge': r['code_challenge']
        } for r in auth_urls], f, indent=2)

if __name__ == '__main__':
    main()
