# Raijin Turbo Documentation

Every page here is a `turbo_docs(action=get_docs, topic=...)` topic, named after its file without `.md`.

## Basics
- [Quickstart](api-quickstart.md) (`api-quickstart`) - Script structure, the request object, globals
- [Engine Types](engines.md) (`engines`) - AUTO vs THREADED vs BURP vs BURP2 vs HTTP3, kettled requests
- [Settings](settings.md) (`settings`) - Complete parameter reference for RequestEngine and queue()

## Advanced
- [Response Processing](response-processing.md) (`response-processing`) - Callbacks, filtering, Burp integration
- [Decorators](decorators.md) (`decorators`) - @MatchStatus, @FilterRegex, and other response filters
- [Race Conditions & Timing Attacks](race-conditions.md) (`race-conditions`) - Gated requests, single-packet attacks, timing
- [Performance Tuning](performance.md) (`performance`) - Maximize requests per second
- [Request Smuggling](desync-techniques.md) (`desync-techniques`) - Desync technique catalog and canary confirmation
- [Wordlists & Utilities](misc.md) (`misc`) - Bruteforce, clipboard, random strings, multi-host

## Montoya API
- [Montoya API Examples](montoya-api-examples.md) (`montoya-api-examples`) - Patterns for Burp extension code
- [Resources](resources.md) (`resources`) - Links to the Montoya API docs, source and example extensions

## Example Scripts

`turbo_docs(action=list_examples)` lists every example and `turbo_docs(action=get_example, name=...)` returns one. The files are in [examples/](../examples/):

| Script | Description |
|--------|-------------|
| [default.py](../examples/default.py) | Basic wordlist fuzzing |
| [race-single-packet-attack.py](../examples/race-single-packet-attack.py) | HTTP/2 single-packet race |
| [race-http3.py](../examples/race-http3.py) | HTTP/3 single datagram race |
| [timing.py](../examples/timing.py) | Statistical timing analysis |
| [recursive.py](../examples/recursive.py) | Recursive directory scanning |
| [burpIntegration.py](../examples/burpIntegration.py) | Burp API integration |
| [multiHost.py](../examples/multiHost.py) | Multi-host scanning |
| [desync-smuggler.py](../examples/desync-smuggler.py) | CL.TE / TE.CL technique sweep with canary confirmation |
| [desync-h2-downgrade.py](../examples/desync-h2-downgrade.py) | HTTP/2 downgrade technique sweep |
| [0cl-poc.py](../examples/0cl-poc.py) | 0.CL desync proof of concept |

## External Links

- [Turbo Intruder: Embracing the billion-request attack](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) - Original blog post
- [Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine) - Single-packet attack research
- [Listen to the whispers](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work) - Web timing attacks
- [HTTP/3 Support](https://portswigger.net/research/100000-requests-per-second-over-wifi) - Introduction of the HTTP3 engine
