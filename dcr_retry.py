import json, concurrent.futures, hashlib, base64, os, urllib.request, urllib.error, urllib.parse, ssl, sys, time, uuid

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

REDIRECT_URI_PRIMARY = "https://claude.ai/api/mcp/auth_callback"
REDIRECT_URI_FALLBACK = "http://127.0.0.1/callback"

def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge

def register_with_body(server, body, user_agent='Mozilla/5.0'):
    """Try DCR with a specific body and user-agent"""
    domain = server.get('domain', '')
    reg_endpoint = server.get('registration_endpoint', '')
    auth_endpoint = server.get('authorization_endpoint', '')
    token_endpoint = server.get('token_endpoint', '')
    
    if not reg_endpoint or reg_endpoint == 'N/A':
        return None
    
    code_verifier, code_challenge = generate_pkce()
    
    req = urllib.request.Request(reg_endpoint, 
        data=json.dumps(body).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': user_agent},
        method='POST')
    resp = urllib.request.urlopen(req, timeout=10, context=ssl_ctx)
    body_resp = resp.read().decode('utf-8', errors='replace')
    reg_data = json.loads(body_resp)
    
    client_id = reg_data.get('client_id', '')
    if not client_id:
        return None
    
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI_PRIMARY,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'scope': body.get('scope', ''),
        'state': uuid.uuid4().hex[:16]
    }
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}" if auth_endpoint and auth_endpoint != 'N/A' else None
    
    return {
        'domain': domain,
        'client_id': client_id,
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'authorization_url': auth_url,
        'authorization_endpoint': auth_endpoint if auth_endpoint != 'N/A' else None,
        'token_endpoint': token_endpoint if token_endpoint != 'N/A' else None,
        'registration_endpoint': reg_endpoint,
        'scopes': body.get('scope', '')
    }

def retry_error(server):
    """Try different body formats for failed servers"""
    domain = server.get('domain', '')
    error = server.get('error', '')
    error_body = server.get('error_body', '')
    reg_endpoint = server.get('registration_endpoint', '')
    
    if not reg_endpoint or reg_endpoint == 'N/A':
        return None
    
    # Try 1: No scope, just redirect URIs
    if 'HTTP 400' in error:
        body1 = {
            "redirect_uris": [REDIRECT_URI_PRIMARY],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_name": f"mcp-client-{domain.replace('.', '-')[:40]}"
        }
        try:
            result = register_with_body(server, body1)
            if result:
                return result
        except:
            pass
        
        # Try 2: Only primary redirect URI, no scope
        body2 = {
            "redirect_uris": [REDIRECT_URI_PRIMARY],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "client_name": f"mcp-client-{domain.replace('.', '-')[:40]}"
        }
        try:
            result = register_with_body(server, body2)
            if result:
                return result
        except:
            pass
        
        # Try 3: With fallback only
        body3 = {
            "redirect_uris": [REDIRECT_URI_FALLBACK],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "client_name": f"mcp-client-{domain.replace('.', '-')[:40]}"
        }
        try:
            result = register_with_body(server, body3)
            if result:
                return result
        except:
            pass
    
    # Try 403 errors with different user-agent
    if 'HTTP 403' in error:
        for ua in ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 
                   'curl/8.0', 
                   'python-requests/2.31']:
            try:
                body = {
                    "redirect_uris": [REDIRECT_URI_PRIMARY],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "client_name": f"mcp-client-{domain.replace('.', '-')[:40]}"
                }
                result = register_with_body(server, body, user_agent=ua)
                if result:
                    return result
            except:
                pass
    
    return None

def main():
    with open('/home/user/dcr_results.json') as f:
        data = json.load(f)
    
    errors = data['errors']
    print(f"Retrying {len(errors)} failed registrations...", file=sys.stderr)
    
    success = []
    still_failed = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(retry_error, e): e for e in errors}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                success.append(result)
            completed += 1
            if completed % 200 == 0:
                print(f"Retry progress: {completed}/{len(errors)}, recovered: {len(success)}", file=sys.stderr)
    
    # Load existing successful registrations
    existing = data['successful_registrations']
    
    # Merge
    all_registrations = existing + success
    
    output = {
        'total': len(all_registrations),
        'original_success': len(existing),
        'retry_recovered': len(success),
        'registrations': all_registrations
    }
    
    with open('/home/user/dcr_all.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    # Auth URLs file
    auth_urls = [r for r in all_registrations if r.get('authorization_url')]
    with open('/home/user/auth_urls.json', 'w') as f:
        json.dump([{
            'domain': r['domain'],
            'authorization_url': r['authorization_url'],
            'authorization_endpoint': r.get('authorization_endpoint'),
            'token_endpoint': r.get('token_endpoint'),
            'client_id': r.get('client_id'),
            'code_verifier': r.get('code_verifier'),
            'code_challenge': r.get('code_challenge')
        } for r in auth_urls], f, indent=2)
    
    print(json.dumps({
        'total_registered': len(all_registrations),
        'retry_recovered': len(success),
        'auth_urls_generated': len(auth_urls),
        'still_failed': len(errors) - len(success)
    }))

if __name__ == '__main__':
    main()
