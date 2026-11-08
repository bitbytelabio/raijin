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

DETECT_REFLECTION = True

PATH_RE = re.compile(r'(?<!/)/[a-zA-Z0-9._~\-][a-zA-Z0-9._~\-/%+:]*(?:\?[^\s"\'<>]*)?')
MAX = 500

LINK_CONTENT_TYPES = ['text/html', 'text/plain', 'javascript', 'xml']


def should_extract_links(response):
    headers = (response or '').split('\r\n\r\n')[0]
    for line in headers.split('\r\n'):
        if line.lower().startswith('content-type:'):
            ct = line.split(':', 1)[1].strip().lower()
            return any(t in ct for t in LINK_CONTENT_TYPES)
    return True  # no Content-Type header -> extract


class MicroCrawl:
    def __init__(self, canary=None, detect_reflection=DETECT_REFLECTION, max_requests=MAX):
        self.seen = set()
        self.count = 0
        self.canary = canary or randstr()
        self.detect_reflection = detect_reflection
        self.max_requests = max_requests
        self.results = []

    def queue_path(self, engine, template, path):
        if self.count >= self.max_requests:
            return
        dedup = path.split('?')[0]
        if dedup in self.seen:
            return
        self.seen.add(dedup)
        self.count += 1
        actual_path = path
        if self.detect_reflection:
            sep = '&' if '?' in path else '?'
            actual_path = path + sep + 'z=' + self.canary
        engine.queue(template, actual_path, label=dedup)

    def handle_response(self, req, table):
        if req.status == 0:
            return

        if should_extract_links(req.response):
            for path in PATH_RE.findall(req.response or ''):
                self.queue_path(req.engine, req.template, path)

        if req.status != 404:
            if self.detect_reflection and self.canary in (req.response or ''):
                req.label = req.label + ' reflection'
            self.results.append({'path': req.label, 'status': req.status, 'response': req.response})
            table.add(req)


# --- Standalone mode ---

_crawl = MicroCrawl()


def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.BURP,
                           maxQueueSize=MAX
                           )

    from burp.api.montoya.http.message.requests import HttpRequest
    base = HttpRequest.httpRequestFromUrl(target.endpoint + "/").toString()
    template = base.replace("GET / ", "GET %s ", 1)

    _crawl.queue_path(engine, template, '/')
    for word in WORDLIST:
        path = word if word.startswith('/') else '/' + word
        _crawl.queue_path(engine, template, path)


def handleResponse(req, interesting):
    _crawl.handle_response(req, table)
