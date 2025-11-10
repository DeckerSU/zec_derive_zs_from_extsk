# zec_derive_zs_from_extsk

A Rust utility for deriving Zcash Sapling (ZS) addresses and viewing/spending keys from private keys in hex or WIF format.

## Description

This tool derives ZS addresses and extended viewing/spending keys using the same algorithm as [komodo_defi_framework (kdf)](https://github.com/KomodoPlatform/komodo-defi-framework) and Komodo wallet. It supports both hex-encoded private keys and base58-encoded WIF (Wallet Import Format) private keys.

## Features

- Derive ZS addresses from private keys
- Support for hex-encoded private keys (64 characters)
- Support for base58-encoded WIF private keys (compressed format)
- Generate Extended Spending Keys and Full Viewing Keys
- Compatible with Komodo wallet and kdf derivation algorithm

## Usage

```bash
zec_derive_zs_from_extsk <private_key_hex|wif_base58> [mainnet|testnet]
```

### Examples

**Hex private key:**
```bash
zec_derive_zs_from_extsk 907ece717a8f94e07de7bf6f8b3e9f91abb8858ebf831072cdbb9016ef53bc5d
```

**WIF base58 private key:**
```bash
zec_derive_zs_from_extsk UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh
```

**Testnet:**
```bash
zec_derive_zs_from_extsk <private_key> testnet
```

## Output

The tool outputs:
- Network (mainnet/testnet)
- Private key (iguana_key) in hex format
- Key components: ask, nsk, ovk, dk
- Extended Spending Key (bech32 encoded)
- Full Viewing Key (bech32 encoded)
- ZS address (bech32 encoded)

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## License

Copyright (c) Decker, 2025

