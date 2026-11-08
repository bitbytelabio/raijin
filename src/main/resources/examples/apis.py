def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           engine=Engine.BURP # Use Burp's HTTP/1 network stack, including upstream proxies etc. You can also use Engine.BURP2 for HTTP/2.
                           )

    # You can find everything under api documented here:
    # https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html

    # Here's a couple of examples:

    # generate a collaborator domain - interactions will appear in the Collaborator tab
    # collabDomain = api.collaborator().defaultPayloadGenerator().generatePayload()

    # invoke AI because why not?
    # api.ai().prompt().execute("Prompt goes here").content()

    # Add a result to the site map:
    # api.siteMap().add(req.getMontoyaRequest())
    # The full Montoya API is available as `api`:
    # https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/montoya-api
    while True:
        engine.queue(target.req)


def handleResponse(req, interesting):
    table.add(req)

