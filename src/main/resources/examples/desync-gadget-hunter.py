import re

WORDLIST = [
    'robots.txt', 'sitemap.xml', 'security.txt', 'static', 'public',
    'images/', 'img', 'css', 'css/', 'js/', 'fonts', 'media',
    'humans.txt', 'ads.txt', 'favicon.ico', 'manifest.json',
    'site.webmanifest', 'apple-touch-icon.png', 'browserconfig.xml',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    '.well-known', '.well-known/security.txt', '.well-known/change-password',
    '.well-known/assetlinks.json', '.well-known/apple-app-site-association',
    'index.html', 'index.php', 'home', 'about', 'contact', 'pricing',
    'products', 'product', 'services', 'service', 'features',
    'blog', 'news', 'articles', 'press', 'careers', 'jobs',
    'support', 'help', 'docs', 'documentation', 'faq',
    'terms', 'privacy', 'search', 'login', 'logout',
    'signup', 'register', 'account', 'profile', 'settings',
    'dashboard', 'portal', 'app', 'assets',
    'api', 'api/',
]

PATH_RE = re.compile(r'(?<!/)/[a-zA-Z0-9._~\-][a-zA-Z0-9._~\-/%+:]*(?:\?[^\s"\'<>]*)?')
CRAWL_MAX = 500
LINK_CONTENT_TYPES = ['text/html', 'text/plain', 'javascript', 'xml']

MARKER = 'esmxfzq'
HEADER_PROBE = 'wrt<'


# --- Crawl helpers (from micro-crawl.py) ---

def should_extract_links(response):
    headers = (response or '').split('\r\n\r\n')[0]
    for line in headers.split('\r\n'):
        if line.lower().startswith('content-type:'):
            ct = line.split(':', 1)[1].strip().lower()
            return any(t in ct for t in LINK_CONTENT_TYPES)
    return True


# --- Redirect helpers ---

def get_location(response):
    if not response:
        return None
    for line in response.split('\r\n'):
        if line.lower().startswith('location:'):
            return line.split(':', 1)[1].strip()
    return None


def is_redirect(status):
    return status in (301, 302, 303, 307, 308)


def is_local_redirect(status, response, host):
    if not is_redirect(status):
        return False
    location = get_location(response)
    if not location:
        return False
    if location.startswith('/'):
        return True
    lower = location.lower()
    if lower.startswith('http://') or lower.startswith('https://'):
        loc_host = location.split('//')[1].split('/')[0].split(':')[0].lower()
        return loc_host == host.lower()
    return False


def extract_root_folders(paths):
    folders = set()
    for path in paths:
        parts = path.strip('/').split('/')
        if len(parts) > 1:
            folders.add('/' + parts[0])
    return folders


# --- Request builders ---

def make_request(path, host, extra_headers=None, absolute_url_host=None, body=None, method=None):
    if method is None:
        method = 'POST' if body is not None else 'GET'
    if absolute_url_host:
        request_line = method + ' https://' + absolute_url_host + path + ' HTTP/1.1'
    else:
        request_line = method + ' ' + path + ' HTTP/1.1'
    lines = [request_line, 'Host: ' + host]
    if extra_headers:
        lines.extend(extra_headers)
    if body is not None:
        lines.append('Content-Type: application/x-www-form-urlencoded')
        lines.append('Content-Length: ' + str(len(body)))
    lines.append('Connection: close')
    lines.append('')
    if body is not None:
        lines.append(body)
    else:
        lines.append('')
    return '\r\n'.join(lines)


# --- Scan: find_redir_gadget ---

def queue_redirect_tests(engine, host, path):
    """Queue exploitation tests for a path that returns a local redirect."""

    # Test 1: Host prefix
    prefixed_host = MARKER + '.' + host
    engine.queue(make_request(path, prefixed_host), label='redir-test:host-prefix:' + path)

    # Test 2: X-Forwarded-Host
    engine.queue(make_request(path, host, extra_headers=[
        'X-Forwarded-Host: ' + MARKER + '.com',
    ]), label='redir-test:xfh:' + path)

    # Test 3: Absolute URL in request line, normal Host
    engine.queue(make_request(path, host, absolute_url_host=MARKER + '.com'),
                 label='redir-test:absolute-url:' + path)

    # Test 4: Absolute URL with real host + injected Host header
    engine.queue(make_request(path, MARKER + '.com', absolute_url_host=host),
                 label='redir-test:absolute-url+host:' + path)

    # Test 5: Host casing
    if host and host[0].islower():
        cased_host = host[0].upper() + host[1:]
    elif host and host[0].isupper():
        cased_host = host[0].lower() + host[1:]
    else:
        cased_host = host
    engine.queue(make_request(path, cased_host), label='redir-test:casing:' + path + '|' + cased_host)


def handle_redir_test(req, host):
    """Handle a redirect exploitation test response. Returns True if handled."""
    label = req.label or ''
    if not label.startswith('redir-test:'):
        return False

    location = get_location(req.response) or ''
    # Parse label: redir-test:<test_type>:<path>[|<extra>]
    rest = label[len('redir-test:'):]
    colon = rest.find(':')
    test_type = rest[:colon] if colon >= 0 else rest
    path_and_extra = rest[colon + 1:] if colon >= 0 else ''
    path = path_and_extra.split('|')[0]

    if test_type == 'casing':
        extra = path_and_extra.split('|')[1] if '|' in path_and_extra else ''
        if extra and extra in location:
            req.label = 'redir:casing ' + path
            table.add(req)
    elif MARKER in location.lower():
        req.label = 'redir:' + test_type + ' ' + path
        table.add(req)

    return True


# --- Scan: find_header_reflect ---

def get_response_headers(response):
    if not response:
        return ''
    return response.split('\r\n\r\n')[0]


def queue_header_reflect_tests(engine, host, path):
    """Queue tests to check if input is reflected unencoded in response headers."""

    # Test 1: Query string parameter
    sep = '&' if '?' in path else '?'
    engine.queue(make_request(path + sep + 'wrt=' + HEADER_PROBE, host),
                 label='header-reflect:query:' + path)

    # Test 2: In the path
    engine.queue(make_request(path + '/' + HEADER_PROBE, host),
                 label='header-reflect:path:' + path)

    # Test 3: X-Request-ID header
    engine.queue(make_request(path, host, extra_headers=[
        'X-Request-ID: ' + HEADER_PROBE,
    ]), label='header-reflect:xrid:' + path)


def handle_header_reflect_test(req):
    """Handle a header reflection test response. Returns True if handled."""
    label = req.label or ''
    if not label.startswith('header-reflect:'):
        return False

    headers = get_response_headers(req.response)
    rest = label[len('header-reflect:'):]
    colon = rest.find(':')
    test_type = rest[:colon] if colon >= 0 else rest
    path = rest[colon + 1:] if colon >= 0 else ''

    if HEADER_PROBE in headers:
        req.label = 'header-reflect:' + test_type + ' ' + path
        table.add(req)

    return True


# --- Main orchestration ---

_crawl_seen = set()
_crawl_count = 0
_canary = None
_redirect_probed = set()
_normalization_probed = set()
_header_reflect_probed = set()
_body_reflect_probed = set()
_host = None
_pre_seeded = False


def _queue_crawl_path(engine, template, path):
    global _crawl_count
    if _crawl_count >= CRAWL_MAX:
        return
    dedup = path.split('?')[0]
    if dedup in _crawl_seen:
        return
    _crawl_seen.add(dedup)
    _crawl_count += 1
    actual_path = path
    sep = '&' if '?' in path else '?'
    actual_path = path + sep + 'z=' + _canary
    engine.queue(template, actual_path, label='crawl:' + dedup)


def _queue_redirect_probe(engine, path):
    if path in _redirect_probed:
        return
    _redirect_probed.add(path)
    engine.queue(make_request(path, _host), label='redir-probe:' + path)


def _queue_normalization_probes(engine, path):
    if path in _normalization_probed:
        return
    _normalization_probed.add(path)

    # Case normalization (IIS especially): toggle case of first alpha char in last segment
    segments = path.rstrip('/').rsplit('/', 1)
    if len(segments) == 2 and segments[1]:
        last = segments[1]
        for i, ch in enumerate(last):
            if ch.isalpha():
                toggled = ch.lower() if ch.isupper() else ch.upper()
                mutated_last = last[:i] + toggled + last[i+1:]
                mutated_path = segments[0] + '/' + mutated_last
                if path.endswith('/'):
                    mutated_path += '/'
                engine.queue(make_request(mutated_path, _host), label='redir-probe:case:' + path)
                break

    # Double slash: //path
    engine.queue(make_request('/' + path, _host), label='redir-probe:dslash:' + path)

    # Dot segment: /./path and /%2e/path
    engine.queue(make_request('/.' + path, _host), label='redir-probe:dot:' + path)
    engine.queue(make_request('/%2e' + path, _host), label='redir-probe:enc-dot:' + path)

    # Encoded slash (trailing): /path%2f
    engine.queue(make_request(path.rstrip('/') + '%2f', _host), label='redir-probe:enc-slash:' + path)

    # Encoded slash (leading): /%2fpath
    engine.queue(make_request('/%2f' + path.lstrip('/'), _host), label='redir-probe:enc-slash:' + path)


def _queue_header_reflect_probe(engine, path):
    if path in _header_reflect_probed:
        return
    _header_reflect_probed.add(path)
    queue_header_reflect_tests(engine, _host, path)


def _queue_body_reflect_probe(engine, path):
    if path in _body_reflect_probed:
        return
    _body_reflect_probed.add(path)
    engine.queue(make_request(path, _host, body='z=' + MARKER, method='POST'),
                 label='body-reflect:post:' + path)
    engine.queue(make_request(path, _host, body='z=' + MARKER, method='GET'),
                 label='body-reflect:get:' + path)


def queueRequests(target, wordlists):
    global _canary, _host, _pre_seeded
    _canary = randstr()
    _host = target.endpoint.replace('https://', '').replace('http://', '').split(':')[0].split('/')[0]

    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.BURP,
                           maxQueueSize=5000
                           )

    from burp.api.montoya.http.message.requests import HttpRequest
    base = HttpRequest.httpRequestFromUrl(target.endpoint + "/").toString()
    template = base.replace("GET / ", "GET %s ", 1)

    base_input = target.baseInput.strip() if hasattr(target, 'baseInput') and target.baseInput else ''
    if base_input.startswith('['):
        # Pre-seeded mode: parse crawl results, skip crawling
        _pre_seeded = True
        crawl_results = eval(base_input)  # list of {"path": ..., "status": ...}
        paths = [r['path'] for r in crawl_results]

        # Queue redirect probes: root folders + special paths
        for folder in extract_root_folders(paths):
            _queue_redirect_probe(engine, folder)
            _queue_normalization_probes(engine, folder)

        # Re-probe paths that were redirects in the crawl
        for r in crawl_results:
            if is_redirect(r.get('status', 0)):
                _queue_redirect_probe(engine, r['path'])
                _queue_normalization_probes(engine, r['path'])
                _queue_header_reflect_probe(engine, r['path'])
    else:
        # Full mode: crawl first, scans run as redirects are discovered
        _pre_seeded = False
        _queue_crawl_path(engine, template, '/')
        for word in WORDLIST:
            path = word if word.startswith('/') else '/' + word
            _queue_crawl_path(engine, template, path)

    # Always probe root with normalization transforms
    _queue_normalization_probes(engine, '/')


def handleResponse(req, interesting):
    if req.status == 0:
        return

    label = req.label or ''

    # Handle body reflection tests
    if label.startswith('body-reflect:'):
        rest = label[len('body-reflect:'):]
        colon = rest.find(':')
        test_type = rest[:colon] if colon >= 0 else rest
        path = rest[colon + 1:] if colon >= 0 else ''
        if MARKER in (req.response or ''):
            req.label = 'body-reflect:' + test_type + ' ' + path
            table.add(req)
        return

    # Handle header reflection tests
    if handle_header_reflect_test(req):
        return

    # Handle redirect exploitation tests
    if handle_redir_test(req, _host):
        return

    # Handle redirect probes
    if label.startswith('redir-probe:'):
        rest = label[len('redir-probe:'):]
        # Labels: redir-probe:/path (plain) or redir-probe:type:/path (normalization)
        if rest.startswith('/'):
            probe_type = None
            path = rest
        else:
            colon = rest.find(':')
            probe_type = rest[:colon] if colon >= 0 else rest
            path = rest[colon + 1:] if colon >= 0 else rest
        if is_local_redirect(req.status, req.response, _host):
            tag = probe_type or 'local'
            req.label = 'redir:' + tag + ' ' + path
            table.add(req)
            queue_redirect_tests(req.engine, _host, path)
            _queue_header_reflect_probe(req.engine, path)
        return

    # Handle crawl responses
    if label.startswith('crawl:'):
        path = label[len('crawl:'):]
        if should_extract_links(req.response):
            for found_path in PATH_RE.findall(req.response or ''):
                _queue_crawl_path(req.engine, req.template, found_path)

        if req.status != 404:
            if _canary and _canary in (req.response or ''):
                req.label = path + ' reflection'
                _queue_body_reflect_probe(req.engine, path)
            else:
                req.label = path
            table.add(req)

            # Queue redirect probes for root folders as we discover paths
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                _queue_redirect_probe(req.engine, '/' + parts[0])
                _queue_normalization_probes(req.engine, '/' + parts[0])

            # If crawl itself found a redirect, probe it and test header reflection
            if is_local_redirect(req.status, req.response, _host):
                _queue_redirect_probe(req.engine, path)
                _queue_normalization_probes(req.engine, path)
                _queue_header_reflect_probe(req.engine, path)
