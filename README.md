# JWT Algorithm Confusion (Public Key Exposed)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Research](https://img.shields.io/badge/Security-Research-blue.svg)](https://github.com/yourusername/web-shell-race-condition)

# Table of Contents

- [Overview](#overview)
- [My "Aha" Moment](#my-aha-moment)
- [Background](#backgroud)
- [Root Cause](#root-cause)
- [Exploitation](#exploitation)
- [Mitigation](#mitigation)
- [Tools](#tools-resources)
- [References](#references)

  # Overview
A server that trusts the JWT `alg` header can be tricked into verifying an RSA-signed token as HMAC. If the public key is exposed, an attacker can use it as an HMAC secret to forge tokens (e.g., escalate to admin) without the private key.

# My "Aha" Moment!

While working on JWT Algorithm Confusion (Public Key Exposed) lab, I noticed the vulnerability wasn't just "use public key as secret" It was that the server was blindly using whatever key material was provided under the kid header or default key, without validating whether the algorithm made cryptographic sense. When I forced HS256, the library took the public bytes as symmetric secret, no verification that it was suppose to be an asymmetric.Tht tiny mismatch between what the signer intended (RSA public and privat key pair) and what the verifier accepted was the entire exploit. Before that I was thinking "how do I trick the signature check?" but the real insight was that the algorithm switch creates a type of confusion at crypto layer, asymmetric public key becomes symmetric secret key.

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


<img width="1363" height="732" alt="User login" src="https://github.com/user-attachments/assets/dcfb432c-504a-4364-b09a-5f014925411e" />

<img width="1352" height="722" alt="image" src="https://github.com/user-attachments/assets/b79bc9a8-9e3a-4c53-b8c7-87bd49183697" />

<img width="1029" height="734" alt="image" src="https://github.com/user-attachments/assets/0f5cd36d-3d8a-47ae-a368-4adc06cfb929" />

<img width="1357" height="739" alt="image" src="https://github.com/user-attachments/assets/375b4440-2df5-4a86-9be8-98df15eb2144" />
<p align="center"></i></p>
<br><br>

To find an exposed public key, I probed common endpoints like `/jwks.json` and discovered a JWK set containing the RSA public key. I observed that attempting to access the admin endpoint directly returned a 401 unauthorized status code.


<img width="1165" height="710" alt="image" src="https://github.com/user-attachments/assets/0b396f4a-7a7d-4146-8aa7-5e525ace4d6f" />
<p align="center"></i></p>
<br><br><br>

**Phase 1: Key Conversion**  
I converted the JWK to PEM format using Burp's JWK Editor, then base64-encoded the PEM to use as a symmetric HMAC secret. Next, I generated a new symmetric key entry in the JWT Editor and replaced its `k` value with the base64-encoded PEM.


<img width="1057" height="728" alt="image" src="https://github.com/user-attachments/assets/c4435306-b0d6-4eed-9a04-e0f1068f045e" />

<img width="1119" height="714" alt="image" src="https://github.com/user-attachments/assets/98b86ac5-c2ed-4fd5-942c-a73d905ff7d6" />

<img width="1353" height="518" alt="image" src="https://github.com/user-attachments/assets/d78a841f-b8db-46f2-adcd-fec17a210364" />

<img width="1079" height="708" alt="image" src="https://github.com/user-attachments/assets/767c1a32-bcf3-4b42-a8fd-2ca49c5d088e" />

<img width="1114" height="709" alt="image" src="https://github.com/user-attachments/assets/5b4faa48-cf90-47a6-a3eb-a07d5ffb157a" />
<p align="center"></i></p>
<br><br>


**Phase 2: Token Forgery**  
Back in Repeater, I modified the JWT: changed the header `alg` to `HS256`, kept the original payload, and re-signed it using the public key as the HMAC secret. Sending the forged token to the restricted admin endpoint succeeded, granting access. I then used the admin panel to delete the target user (carlos), completing the lab.

Before Modification


<img width="1032" height="673" alt="image" src="https://github.com/user-attachments/assets/4b699571-814c-4911-97dd-ddc2ef848cb4" />
<p align="center"></i></p>
<br>

After Modification


<img width="1126" height="648" alt="image" src="https://github.com/user-attachments/assets/faa138fa-51a4-456c-8869-45f672951699" />

<img width="1352" height="687" alt="image" src="https://github.com/user-attachments/assets/6d8009f8-be74-42e9-8bc0-68e60ad15f97" />

<img width="1311" height="693" alt="image" src="https://github.com/user-attachments/assets/337b6b8f-8e3c-4980-b0fc-0b25342e3cf6" />

<img width="1349" height="747" alt="image" src="https://github.com/user-attachments/assets/744daa8a-ecd4-48d7-8b60-ee8bdd22c889" />
<p align="center"></i></p>
<br><br>

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
