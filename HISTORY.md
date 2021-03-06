# 0.2.0 / 27-07-2020

**Breaking:**
- PublicKey must be prefixed with '0x04' (to show it is an uncompressed public key)
- PrivateKey must be prefixed with '0x'
- Signature must be prefixed with '0x' and suffixed with v-value 1b/1c

**Enhancements:**

- Switch from hdkey, brorand, secp256k1 and js-sha3 to ethers.js lib
- verifyPayload possible with publicKey or ethereum address
- Node versions 12, 13 and 14 supported
- Security Patches for dependent packages

# 0.1.5 / 26-02-2020

**New features:**
- Compute an address out of a public key with `getAddressFromPubKey(pubkey)`

**Bugfixes:**
- Updated package.json to use TypeScript `~3.4.5` instead of `^3.4.5`

# 0.1.4 / 20-01-2020

**Bugfixes:**
- Downgraded Dist files to TypeScript 3.4.5 due to a [breaking change in 3.7](https://github.com/microsoft/TypeScript/issues/33939)

# 0.1.3 / 08-01-2020

**Enhancements:**
- Updated all dependencies, fixed [CVE-2019-19919](https://github.com/advisories/GHSA-w457-6q6x-cgp9)
- Introduced [HISTORY.md](HISTORY.md)

# 0.1.2 / 24-12-2019

**Enhancements:**
- Updated `secp256k1` lib to fix a [Timing Attack vulnerability](https://app.snyk.io/vuln/SNYK-JS-ELLIPTIC-511941)

# 0.1.1 / 20-09-2019

*Initial release*
