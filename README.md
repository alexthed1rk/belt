# STB 34.101.31-2020
Belarusian information technology and security
encryption and integrity control algorithms

Specification: [https://apmi.bsu.by/assets/files/std/belt-spec371.pdf](https://apmi.bsu.by/assets/files/std/belt-spec371.pdf)

## How to Test
Use `test_belt.bat` or `test_belt.sh`

## TODO
- [ ] Format preserving encryption: `belt-encrypt-fmt`
- [ ] Format preserving encryption: `belt-decrypt-fmt`
- [ ] SIMD hardware acceleration

## Odin API
| Procedure | Description |
| :--- | :--- |
| `seal_dwp` | Authenticated encryption: `belt-seal-dwp` |
| `open_dwp` | Authenticated encryption: `belt-open-dwp` |
| `seal_che` | Authenticated encryption: `belt-seal-che` |
| `open_che` | Authenticated encryption: `belt-open-che` |
| `seal_kwp` | Key wrap encryption: `belt-seal-kwp` |
| `open_kwp` | Key wrap encryption: `belt-open-kwp` |
| `encrypt_ctr` | Counter encryption: `belt-encrypt-ctr` |
| `decrypt_ctr` | Counter encryption: `belt-decrypt-ctr` |
| `encrypt_cfb` | Cipher feedback encryption: `belt-encrypt-cfb` |
| `decrypt_cfb` | Cipher feedback encryption: `belt-decrypt-cfb` |
| `encrypt_ecb` | Electronic codebook encryption: `belt-encrypt-ecb` |
| `decrypt_ecb` | Electronic codebook encryption: `belt-decrypt-ecb` |
| `encrypt_cbc` | Cipher block chaining encryption: `belt-encrypt-cbc` |
| `decrypt_cbc` | Cipher block chaining encryption: `belt-decrypt-cbc` |
| `derive_mac` | Message authentication code derivation: `belt-derive-mac` |
| `derive_hash` | Hash derivation: `belt-derive-hash` |
| `encrypt_bde` | Block level encryption: `belt-encrypt-bde` |
| `decrypt_bde` | Block level encryption: `belt-decrypt-bde` |
| `encrypt_sde` | Sector level encryption: `belt-encrypt-sde` |
| `decrypt_sde` | Sector level encryption: `belt-decrypt-sde` |
| `expand_key` | Expand `key128`, `key192` to `key256`: `belt-expand-key` |
| `derive_key` | Derive `key128`, `key192`, `key256` from `key128`, `key192`, `key256`: `belt-derive-key` |
