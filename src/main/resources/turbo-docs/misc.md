# Wordlists & Utilities

Additional features for scripting.

## Wordlists

### File Wordlists

```python
for word in open('/usr/share/dict/words'):
    engine.queue(target.req, word.rstrip())
```

### Clipboard

Lines from your clipboard:

```python
for word in wordlists.clipboard:
    engine.queue(target.req, word)
```

### Observed Words

Words collected during Burp passive scanning:

```python
for word in wordlists.observedWords:
    engine.queue(target.req, word)
```

### Bruteforce Generator

Infinite incremental bruteforce (a, b, ... aa, ab, ...):

```python
seed = 0
while True:
    batch = []
    seed = wordlists.bruteforce.generate(seed, 5000, batch)
    for word in batch:
        engine.queue(target.req, word)
```

## Utility Functions

`randstr`, `mean`, `stddev` and `queueForever` are defined before your script runs, like the
decorators: call them directly. There is no `ScriptEnvironment` module to import from.

### Random Strings

```python
randstr()           # 12 char alphanumeric
randstr(8)          # 8 char alphanumeric
randstr(8, False)   # 8 char letters only
```

### Cache Busting

Use `$randomplz` in requests or payloads:

```python
engine.queue(target.req, "$randomplz")
```

Replaced with random 10-character alphanumeric string.

### Statistical Functions

```python
def completed(reqsFromTable):
    times = [req.time for req in reqsFromTable]   # microseconds
    print(mean(times), stddev(times))
```

## Global Variables

| Variable | Type | Description |
|----------|------|-------------|
| `target` | obj | `.endpoint`, `.req`, `.baseInput` |
| `wordlists` | obj | `.clipboard`, `.observedWords`, `.bruteforce` |
| `table` | ResultStore | Results table: `table.add(req)`, `table.setSortOrder(column, descending)` |
| `handler` | RunHandler | Run control |
| `api` | MontoyaApi | Montoya API |
| `host` | str | Target hostname |
| `turbo` | obj | Engine classes (`turbo.DesyncTechniques`, `turbo.Utils`, ...); `import io...` does not work in Jython |

## Target Object

```python
target.endpoint  # "https://example.com:443"
target.req       # Full HTTP request with %s markers
target.baseInput # The text the %s marker replaced in the Turbo dialog, or base_input over MCP
```

## Handler Object

```python
handler.setMessage("Processing...")  # Update status bar
handler.abort()                       # Cancel run
```

## Engine User State

Store custom state across callbacks:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)
    engine.userState['counter'] = 0
    ...

def handleResponse(req, interesting):
    req.engine.userState['counter'] += 1
```

## Multi-Host Runs

Override endpoint per-request:

```python
hosts = ['host1.com', 'host2.com', 'host3.com']

for host in hosts:
    endpoint = 'https://' + host + ':443'
    engine.queue(target.req, payload, endpoint=endpoint)
```

## Output to File

```python
def handleResponse(req, interesting):
    with open('output.txt', 'a') as f:
        f.write(req.words[0] + '\n')
    table.add(req)
```

## Example Scripts

- [specialWordlists.py](../examples/specialWordlists.py) - Wordlist sources
- [multiHost.py](../examples/multiHost.py) - Multi-host scanning
- [outputToFile.py](../examples/outputToFile.py) - File output
