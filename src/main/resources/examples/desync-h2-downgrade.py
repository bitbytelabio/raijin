# HTTP/2-downgrade desync sweep: the h2* family in turbo.DesyncTechniques obfuscates the
# Transfer-Encoding header (or injects a bogus pseudo-header) in ways only meaningful once an
# HTTP/2-to-HTTP/1.1 downgrading gateway re-serializes the request — HTTP/2 itself has no
# Transfer-Encoding header and represents request-line fields as pseudo-headers, so these
# techniques only matter if something downstream turns this back into HTTP/1.1 text.
#
# Raijin's Engine.BURP2/HTTP2RequestEngine already rewrite the exact "^ -> \r, ~ -> \n, ` -> :"
# marker convention DesyncTechniques.apply() produces for the h2* cases (see http2.py) into real
# HTTP/2 pseudo-headers/frames — no extra translation needed here.
#
# Unlike desync-smuggler.py, this doesn't attempt automated canary-based confirmation: a
# downgrading gateway's actual behavior on a mismatched/duplicated pseudo-header varies too much
# to assume one verdict shape. Read the responses (and, where relevant, whether the backend saw
# a smuggled follow-up) manually. target.baseInput, if set, overrides the technique list
# (comma-separated).

H2_TECHNIQUES = [
    'h2colon', 'h2auth', 'h2path', 'http2case', 'h2scheme', 'h2name', 'h2method',
    'h2space', 'h2prefix', 'http2hide', 'h2CL',
]


def queueRequests(target, wordlists):
    host = target.endpoint.replace('https://', '').replace('http://', '').split(':')[0].split('/')[0]

    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           engine=Engine.BURP2,
                           )

    base_input = target.baseInput.strip() if hasattr(target, 'baseInput') and target.baseInput else ''
    techniques = [t.strip() for t in base_input.split(',') if t.strip()] if base_input else H2_TECHNIQUES

    base = ('POST / HTTP/1.1\r\n'
            'Host: ' + host + '\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            'Transfer-Encoding: chunked\r\n'
            '\r\n'
            '0\r\n\r\n')

    for technique in techniques:
        mutated = turbo.DesyncTechniques.apply(base, 'Transfer-Encoding', technique)
        if mutated is None:
            continue
        engine.queue(mutated, label=technique)


def handleResponse(req, interesting):
    # No automated verdict (see header comment) — record everything for manual review, and
    # call out anything that didn't come back as an ordinary response.
    table.add(req)
    if req.status not in (200, 301, 302, 303, 304, 400, 404, 502):
        req.label = (req.label or '') + ' (unusual status - inspect manually)'
