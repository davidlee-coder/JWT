# JWT Algorithm Confusion (Public Key Exposed)

A server that trusts the JWT `alg` header can be tricked into verifying an RSA-signed token as HMAC. If the public key is exposed, an attacker can use it as an HMAC secret to forge tokens (e.g., escalate to admin) without the private key.

## Background

JWT signing modes:

- **Symmetric (HS256, HS384, HS512):** single shared secret used for both signing and verification (HMAC).
- **Asymmetric (RS256, RS384, RS512):** private key signs, public key verifies (RSA).

Many libraries decide verification logic based on the token's `alg` header. Because that header is attacker-controlled, failing to enforce the expected algorithm allows an attacker to switch algorithms and bypass verification.

## Root cause

- The server accepts `alg` from the token and uses it to select verification code.
- If both RSA and HMAC verification paths exist, an attacker can change `alg` from `RS256` to `HS256` and supply the public key as the HMAC secret.

Vulnerable pseudocode:

```js
function verifyJWT(token) {
  const header = decodeHeader(token);
  const alg = header.alg; // attacker-controlled
  if (alg === 'HS256') return hmacVerify(token, keys.secret);
  if (alg === 'RS256') return rsaVerify(token, keys.publicKey);
}
```

If `keys.publicKey` is used as the HMAC secret when `alg` is `HS256`, verification will succeed without the private key.

## Exploitation

I logged in as a normal user (wiener) and captured the login request in Burp Suite. Forwarding it to Repeater, I used the JWT Editor extension to inspect the token and confirmed it used RS256 (RSA-SHA256) for signing.

![Login and token inspection](<User login.png>)
![JWT Editor showing RS256](<repeater tab.png>)
![Repeater setup](<repeater tab-1.png>)
![Token details](<alg RS256.png>)

To find an exposed public key, I probed common endpoints like `/jwks.json` and discovered a JWK set containing the RSA public key. I observed that attempting to access the admin endpoint directly returned a 401 unauthorized status code.

![Admin endpoint access denied](<admin 401.png>)

**Phase 1: Key Conversion**  
I converted the JWK to PEM format using Burp's JWK Editor, then base64-encoded the PEM to use as a symmetric HMAC secret. Next, I generated a new symmetric key entry in the JWT Editor and replaced its `k` value with the base64-encoded PEM.

![JWK to PEM conversion](<Public key.png>)
![PEM base64 encoding](<decoded to base64.png>)
![alt text](<before k replacement.png>)
![Symmetric key generation](<after k replcement.png>)

**Phase 2: Token Forgery**  
Back in Repeater, I modified the JWT: changed the header `alg` to `HS256`, kept the original payload, and re-signed it using the public key as the HMAC secret. Sending the forged token to the restricted admin endpoint succeeded, granting access. I then used the admin panel to delete the target user (carlos), completing the lab.


![JWT modification](<Before alg and sub change.png>)
![Re-signing the token](<after alg and sub change.png>)
![Admin access granted](<admin succes.png>)
![Deleting the user](<admin account takeover.png>)
![Confirmation](<lab solved.png>)

Example JWK snippet (from `/jwks.json`):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "...",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## Mitigations

1. **Enforce expected algorithm** — never trust the token `alg` header. Explicitly require `RS256` (or your chosen algorithm) when verifying tokens.

```js
if (tokenHeader.alg !== 'RS256') throw new Error('Invalid algorithm');
```

2. **Disable unused algorithms** in libraries and configuration (especially `none` and unwanted symmetric algorithms).
3. **Separate verification paths** for symmetric and asymmetric tokens; do not dynamically dispatch solely on the token header.
4. **Rotate and protect keys**; avoid exposing private keys and minimize public key exposure to trusted discovery endpoints guarded by appropriate controls.
5. **Use libraries that require algorithm whitelists** or where verification is bound to a trusted key store.

## Tools

- Burp Suite (JWT Editor, Repeater)
- JWK/JWKs converters or JWT tooling

## References

- PortSwigger lab: JWT authentication bypass via algorithm confusion — https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion

Happy (ethical) hacking!
