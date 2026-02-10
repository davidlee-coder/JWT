# JWT Algorithm Confusion – No Exposed Signing Key
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Research](https://img.shields.io/badge/Security-Research-blue.svg)](https://github.com/yourusername/web-shell-race-condition)

**Level** — Expert <p align="center"></i></p>
<br>

**Category** — JWT Attacks / Algorithm Confusion <p align="center"></i></p>
<br> 
**PortSwigger Link** — https://portswigger.net/web-security/jwt/lab-jwt-algorithm-confusion-no-exposed-key<p align="center"></i></p>
<br>  
**Completed** — February 10 2026<p align="center"></i></p>
<br>  
**Tools** — Burp Repeater, JWT Editor (for signing), Burp Decoder<p align="center"></i></p>
<br>

# Table of Contents

- [Overview](#overview)
- [My Aha Moment](#vulnerability-details)
- [Root Cause](#root-cause)
- [Impact](#impact)
- [Exploitation](#exploitation)
- [Mitigation](#mitigation)
  
# Overview: Algorithm Confusion Without a Public Key

JWT algorithm confusion exploits servers that blindly trust the `alg` header in the token and switch signing/verification algorithms without proper validation. In this variant, **no public key is exposed** (no JWKS endpoint or embedded key), so the attacker must trick the server into using a symmetric algorithm (HS256) while signing with a key it already knows typically the server's own **secret** or **private key** leaked from another context (e.g., source code, misconfigured endpoint, or predictable weak secret).
The attack relies on the server:
- Accepting `alg: HS256` even when the token was originally RS256/ECDSA-signed
- Using the same key material (or derivable material) for both asymmetric verification and symmetric HMAC

This creates a classic type confusion: asymmetric public/private key pair becomes symmetric secret.

# My Aha Moment

The breakthrough came when I stopped looking at the header as a configuration setting and started seeing it as a logic bomb. I realized the server wasn't verifying the type of key it was using—it was blindly pivoting its entire cryptographic process to HMAC based on a user-supplied string. I had been so focused on 'finding' a public key (via JWKS or embedded fields) that I missed the broader architectural flaw: the server already possessed a trusted symmetric secret for HS256. If I could identify that secret—whether leaked via a debug page, source code, or a predictable default—I could sign a forged token as HS256 and force the server to validate it using its own internal key. That realization moving from 'I need their public key' to 'I can use their own symmetric secret against them changed how I view JWT security. It transformed Algorithm Confusion from a simple header trick into a massive key management disaster. Now, whenever I see a controllable alg header without a JWKS endpoint, my first question isn't 'Where is the key?' but rather 'What secret is this server hiding that I can exploit?'.

# Root Cause

- Server trusts `alg` header without validating it matches the expected algorithm for that token/user/session  
- No enforcement of asymmetric-only signing (e.g., reject HS* if RS*/EC* expected)  
- Symmetric secret (for HS256) is stored/configured on the server and reused without isolation  
- No key ID (kid) validation or algorithm pinning → attacker can downgrade to symmetric and supply known/guessable secret

# Impact

- **Full account takeover** — forged admin tokens, escalate privileges (change sub, role, admin flag)  
- **Bypass authentication** — impersonate any user by modifying payload and signing with leaked/guessable secret  
- **Session hijacking** — steal or forge any JWT-based session  
- **Chaining potential** — combine with other flaws (e.g., XSS to steal tokens, IDOR to leak secrets) for broader compromise  
- In real applications (especially legacy SSO or microservices), this can lead to mass account takeover or complete system compromise.

# Exploitation
After logging in as a standard user (wiener), I sent the GET /my-account request to Burp Repeater to begin manual reconnaissance. My first objective was to test the perimeter: I attempted to access the /admin endpoint, which predictably returned a 401 Unauthorized response.
<img width="1258" height="470" alt="image" src="https://github.com/user-attachments/assets/551c853a-6ed5-47c0-85ff-5df50837f46b" />
<img width="1227" height="561" alt="image" src="https://github.com/user-attachments/assets/170666cf-d60a-4915-896d-f2ec0241320f" />
<img width="1277" height="547" alt="image" src="https://github.com/user-attachments/assets/1ba46f76-13db-41a2-b0c3-2013d95b2a71" />
<img width="1028" height="688" alt="image" src="https://github.com/user-attachments/assets/097c2f34-6c82-40c0-85f5-eb92989f376f" />
<p align="center"></i></p>
<br><br>

During this initial probe, I identified that the application relies on JSON Web Tokens (JWT) for session management. Using the Burp JWT Editor extension, I decoded the session cookie and performed a deep-dive into the token's header and payload. I found that the server was utilizing the RS256 (RSA Signature with SHA-256) asymmetric algorithm. This immediately raised a red flag: if I could trigger a 'Type Confusion' by switching the algorithm to HS256, I might be able to trick the server into using its own public key as a symmetric HMAC secret:
<img width="1024" height="680" alt="image" src="https://github.com/user-attachments/assets/ea711733-911a-403f-8cf5-0c6bd389204f" />
<img width="508" height="630" alt="image" src="https://github.com/user-attachments/assets/274af1b2-8b7c-4879-9777-04b64c48acf0" />
<p align="center"></i></p>
<br><br>

When the standard /jwks.json probes returned a 404 Not Found, it was clear the public key wasn't exposed via traditional endpoints. However, I knew the public key could still be mathematically derived if I had enough sample data.The Cryptographic Pivot, I performed two separate logins to capture a pair of unique, valid JWTs. Using the sig2n tool (run via a Docker container for environment consistency), I supplied both tokens to the algorithm.bashdocker run --rm -it portswigger/sig2n <token1> <token2> This tool uses the fact that the RSA signature is essentially \(s=m^{d}\quad (\mod n)\). By comparing two different signatures, the script can solve for the modulus (\(n\)), effectively reconstructing the public key from the wire. This turned a 'black box' environment into a 'gray box' scenario, giving me the exact key material I needed to attempt the HS256 Algorithm Confusion attack.
<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/7b11f92c-075b-41a9-b0f0-cc0b004510dc" />
<img width="1284" height="555" alt="image" src="https://github.com/user-attachments/assets/eb78bf3d-2bcb-4520-a000-17996729bb72" />
<img width="1341" height="172" alt="image" src="https://github.com/user-attachments/assets/e4dc1b0d-cdc4-40bd-8187-40d33e76910d" />
<img width="1349" height="599" alt="image" src="https://github.com/user-attachments/assets/3ed828fc-9734-4356-8fb8-050452bf8b32" />
<p align="center"></i></p>
<br><br>

Running the sig2n tool produced several mathematically valid candidates for the modulus (\(n\)). Since any of these could theoretically be the server's public key, I had to systematically test each one. The tool provided the recovered key in both X.509 and PKCS1 formats, along with pre-signed, tampered JWTs for each variation. I began a manual 'brute-force' to the  GET /my-account path of the candidate tokens. My first several attempts resulted in 302 Redirects to the login page, indicating that the server's signature verification had failed and my session was invalidated. My success came when I tested the token derived from the second X.509-formatted entry. Instead of a redirect, the server responded with a 200 OK, I also switched the alg header to HS256 with the sub claim wiener and still received 200 OK it exposed the mechanism's vulnerability to algorithm confusion attacks. 

Tampered JWT:

`eyJraWQiOiJhYTBlOTMxMS1kMjU2LTRkMzQtODkzMS1kM2ViZjJkMmVjN2EiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAiZXhwIjogMTc3MDU3MzQ1MywgInN1YiI6ICJ3aWVuZXIifQ.sT1XNVr1etCawILgBIsUD7cLzemVIOBMCVCUoJqu70A`

Base64 encoded x509 key:

`LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyL01EU01BNUNoZHUwWUZxVlFaOApLOHFIWStvNjMveFNUVEpESEFHSXdEQlpnZVRKdXZnU2NuQUt2TnVOb0lxZGp2bWlGZVlxQlU3Vnd0WmdIbEgrCkZLclVqeEdvZWhUT2tBd1hRbmt1QnVCd0ZKbnVlazZtZVEwR2I4NXF3N3JGK3ZQdmt1bVdGbmI1WG5qSU1GOUUKQ3FnWDE3bUt0dUwrRndNcjBuajYyOTlXaEdnWFo3ZnBqM21QbkFXRGhGNFNzdjFZL2lHMWtNUEswRytrUzF2cQp1QmRmV00xS25TbnVBaUQ2SkZHVXE1dUllM1p0OXRZY3p3Syt2N2RlRlVGSHplNGhjd2JhbnRCeVNMUmVjam9mCkxBd1BpSE9NbWMxZ1pCNGFhcEtwWGZqQ2J1dkNYMWczSEFGOVNMeFJ5d2NqRE40RW1LUThuc2NaRmtTRXhReCsKRXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==`

<img width="1032" height="649" alt="image" src="https://github.com/user-attachments/assets/8d4e54da-3e49-4fe4-a69e-4f735ea0a576" />
<img width="1037" height="650" alt="image" src="https://github.com/user-attachments/assets/8bea740e-0696-42ba-ba90-05a75d7b39a2" />
<img width="1030" height="678" alt="image" src="https://github.com/user-attachments/assets/3c814ac5-ea61-4a05-8050-967ab8742693" />
<p align="center"></i></p>
<br><br>

To carry out the final forgery, I had to 're-map' the server's public key as a symmetric HMAC secret. I went to Burp Suite JWT Editor Keys tab and created a New Symmetric Key in JWK format. I replaced the placeholder value in the k property with the Base64-encoded public key I previously reconstructed. This was the critical step: by saving this public key material as a symmetric key, I prepared the tool to sign my forged token using HS256. I made sure that I was actually utilizing raw Base64 key material and not a pre-signed token. This was helpful in ensuring I had full control over the payload while the signing operation took place. I was confident that, when I modified the sub claim from wiener to administrator, my signature would be mathematically tied to the server's own 'secret' public key.
<img width="631" height="507" alt="image" src="https://github.com/user-attachments/assets/d2087269-410c-47d8-b22c-c0930f8e0214" />
<img width="621" height="501" alt="image" src="https://github.com/user-attachments/assets/d79778c4-82c0-4002-88dc-f29919c5bb93" />
<p align="center"></i></p>
<br><br>

Having reconstructed the public key and imported it again as a symmetric secret, I went back to the GET request at "/my-account" in Burp Repeater and then modified the path to "/admin". Inside the JWT Editor tab, I carried out the last part of the attack:
The Forgery:

Header Swap: I manually modified alg parameter from "RS256" to "HS256", and the server had to adapt to the changes. I also modified the sub (subject) claim in the wiener payload to administrator.
BEFORE SWITCHING 'sub' claim AND alg headers: 
<img width="1028" height="661" alt="image" src="https://github.com/user-attachments/assets/1aeeb2dd-7d81-4329-a437-33fb4b55a45b" /><p align="center"></i></p>
<br>
AFTER SWITCHING 'sub' claim AND alg headers
<img width="1029" height="657" alt="image" src="https://github.com/user-attachments/assets/15c6fc0c-ad88-4959-8ab0-7b6aa3ccf7e7" /><p align="center"></i></p>
<br>

The Cryptographic Signature: After clicking 'Sign,' a symmetric JWK was selected, which had previously been generated using the server's public key material. The Escalation Following this, upon sending the forged token, it gave me access to the server as I identified where to go on the server (/admin/delete?username=carlos) and redirected this request to the browser, where I could verify this. As a matter of fact, I successfully deleted the user 'carlos,' providing proof that this vulnerability indeed allowed for full privilege escalation on an authorized user's account.
<img width="1029" height="663" alt="image" src="https://github.com/user-attachments/assets/df227980-fb8a-473c-8d5d-6fd3fa2cfaef" />
<img width="1278" height="413" alt="image" src="https://github.com/user-attachments/assets/6ec42edf-5862-4193-9f8d-abd65f8e5e5c" />
<img width="1270" height="462" alt="image" src="https://github.com/user-attachments/assets/e7e72caf-1cea-4024-af88-274f3104700b" />
<p align="center"></i></p>
<br><br>

# Mitigations

- **Reject algorithm switching** — enforce expected `alg` per endpoint/token type (e.g., only allow RS256)  
- **Algorithm pinning** — hardcode allowed algorithms and reject anything else  
- **Separate secrets** — never reuse asymmetric private keys or symmetric secrets across contexts   
- **Strong key validation** — use kid to lookup expected key and algorithm; reject if mismatch  
- **Disable legacy algorithms** — avoid HS256 if asymmetric is required; prefer EdDSA or ES256  
- **Audit JWKS / key exposure** — ensure no debug endpoints leak secrets; use secure key storage

**Happy (ethical) Hacking!**





