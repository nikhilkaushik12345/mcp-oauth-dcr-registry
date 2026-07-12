import json, concurrent.futures, urllib.request, urllib.error, ssl, sys, time

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def visit_url(entry):
    """Visit the authorization URL and capture redirect info"""
    domain = entry.get('domain', '')
    auth_url = entry.get('authorization_url', '')
    reg_endpoint = entry.get('registration_endpoint', '')
    auth_endpoint = entry.get('authorization_endpoint', '')
    token_endpoint = entry.get('token_endpoint', '')
    client_id = entry.get('client_id', '')
    code_verifier = entry.get('code_verifier', '')
    
    if not auth_url:
        return None
    
    result = {
        'domain': domain,
        'authorization_url': auth_url,
        'authorization_endpoint': auth_endpoint,
        'token_endpoint': token_endpoint,
        'registration_endpoint': reg_endpoint,
        'client_id': client_id,
        'code_verifier': code_verifier,
        'redirect_starts_with_mcp': False,
        'redirect_url': None,
        'http_status': None,
        'redirect_chain': []
    }
    
    try:
        req = urllib.request.Request(auth_url, method='GET', 
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'})
        req.redirect_dict = {}
        
        # Don't follow redirects - we want to capture them
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                result['redirect_chain'].append({
                    'code': code,
                    'location': newurl,
                    'starts_with_mcp': newurl.startswith('mcp.') or '://mcp.' in newurl.split('?')[0].lower()
                })
                if newurl.startswith('mcp.') or '://mcp.' in newurl.split('?')[0].lower():
                    result['redirect_starts_with_mcp'] = True
                    result['redirect_url'] = newurl
                return None  # Don't follow
        
        opener = urllib.request.build_opener(NoRedirectHandler)
        resp = opener.open(req, timeout=10)
        result['http_status'] = resp.status
        
        # Check if final redirect has mcp.
        location = resp.headers.get('Location', '')
        if location:
            result['redirect_chain'].append({
                'code': resp.status,
                'location': location,
                'starts_with_mcp': location.startswith('mcp.') or '://mcp.' in location.split('?')[0].lower()
            })
            if location.startswith('mcp.') or '://mcp.' in location.split('?')[0].lower():
                result['redirect_starts_with_mcp'] = True
                result['redirect_url'] = location
        
        # Read body to check for any mcp. redirects in HTML
        try:
            body = resp.read(5000).decode('utf-8', errors='replace')
            if 'mcp.' in body.lower():
                # Check for mcp. URIs
                import re
                mcp_uris = re.findall(r'(?:mcp\.[a-zA-Z0-9.-]+)', body)
                if mcp_uris:
                    result['mcp_uris_in_body'] = mcp_uris[:10]
                    result['redirect_starts_with_mcp'] = True
        except:
            pass
            
    except urllib.error.HTTPError as e:
        result['http_status'] = e.code
        location = e.headers.get('Location', '')
        if location:
            result['redirect_chain'].append({
                'code': e.code,
                'location': location,
                'starts_with_mcp': location.startswith('mcp.') or '://mcp.' in location.split('?')[0].lower()
            })
            if location.startswith('mcp.') or '://mcp.' in location.split('?')[0].lower():
                result['redirect_starts_with_mcp'] = True
                result['redirect_url'] = location
        try:
            body = e.read(5000).decode('utf-8', errors='replace')
            import re
            mcp_uris = re.findall(r'(?:mcp\.[a-zA-Z0-9.-]+)', body)
            if mcp_uris:
                result['mcp_uris_in_body'] = mcp_uris[:10]
        except:
            pass
    except Exception as e:
        result['error'] = str(e)[:200]
    
    return result

def main():
    with open('/home/user/auth_urls.json') as f:
        entries = json.load(f)
    
    print(f"Visiting {len(entries)} authorization URLs...", file=sys.stderr)
    
    results = []
    mcp_redirects = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(visit_url, e): e for e in entries}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                if result.get('redirect_starts_with_mcp'):
                    mcp_redirects.append(result)
            completed += 1
            if completed % 100 == 0:
                print(f"Visit progress: {completed}/{len(entries)}, mcp. redirects: {len(mcp_redirects)}", file=sys.stderr)
    
    output = {
        'total_visited': len(results),
        'mcp_redirects_found': len(mcp_redirects),
        'results': results,
        'mcp_redirects': mcp_redirects
    }
    
    with open('/home/user/visit_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    # Also save all OAuth endpoints
    oauth_endpoints = []
    for r in results:
        oauth_endpoints.append({
            'domain': r['domain'],
            'authorization_endpoint': r.get('authorization_endpoint'),
            'token_endpoint': r.get('token_endpoint'),
            'registration_endpoint': r.get('registration_endpoint'),
            'client_id': r.get('client_id'),
            'code_verifier': r.get('code_verifier'),
            'redirect_starts_with_mcp': r.get('redirect_starts_with_mcp', False),
            'redirect_url': r.get('redirect_url'),
            'http_status': r.get('http_status'),
            'redirect_chain': r.get('redirect_chain', [])
        })
    
    with open('/home/user/oauth_endpoints.json', 'w') as f:
        json.dump(oauth_endpoints, f, indent=2)
    
    print(json.dumps({
        'total_visited': len(results),
        'mcp_redirects_found': len(mcp_redirects),
        'oauth_endpoints_preserved': len(oauth_endpoints)
    }))

if __name__ == '__main__':
    main()
