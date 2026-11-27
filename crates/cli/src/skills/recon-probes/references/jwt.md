# JWT

## Decode first
`run {"do":"util.jwt_decode","token":"<jwt>"}` shows the header and claims.

## `probe.jwt`
`run {"do":"probe.jwt","mode":"analyze","token":"<jwt>"}`. Modes: `analyze`, `forge_none`, `alg_confusion`,
`crack`, `sign` (HMAC secret), `sign_key`, `verify` (says why a key fails), `encrypt`, `decrypt`,
`embed_jwk`, `empty_hmac`, `psychic`, `header_url`.

- Signing modes keep the payload byte for byte unless `payload_overrides` names claims:
  `run {"do":"probe.jwt","mode":"sign","token":"<jwt>","secret":"<secret>","payload_overrides":{}}`.
- `mode` `header_url` with `key_id`, `header` (`jku` or `x5u`) and `url` returns the signed token plus
  `host.body`, the JWK set or PEM certificate chain to serve at that URL (without `key_id` it only sets the
  header): `run {"do":"probe.jwt","mode":"header_url","token":"<jwt>","key_id":"<id>","header":"jku","url":"<url>"}`.
- `decrypt` refuses a password-based token asking for more than 1,000,000 PBES2 iterations.

## `jwt_keys`
The key ring for `probe.jwt`: generate, import, list, export or delete a key (RSA, EC, OKP, oct, password).
`run {"do":"jwt_keys.generate","kty":"RSA","size":2048}`, `run {"do":"jwt_keys.list"}`.

- Each key lists the `modes` it supports (X25519/X448 keys encrypt and decrypt, they do not sign).
- `list` and `export` omit private material unless `include_private` is true:
  `run {"do":"jwt_keys.export","key_id":"<id>","include_private":true}`.
