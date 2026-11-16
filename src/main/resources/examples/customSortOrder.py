# Sets the order of the results from the script with table.setSortOrder(column, descending).
# Columns, numbered from 0: Row, Payload, Status, Anomaly rank, Words, Length, TTFB, TTLB, Arrival,
# Label, Queue ID, Connection ID. The order replaces the automatic sort by anomaly rank on run
# completion, and over MCP it is the default order of turbo_run(action=results).
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)

    # sort by status (column 2), highest first
    table.setSortOrder(2, True)

    for i in range(50):
        if '%s' in target.req:
            engine.queue(target.req, str(i))
        else:
            engine.queue(target.req)
        time.sleep(0.1)


def handleResponse(req, interesting):
    table.add(req)
