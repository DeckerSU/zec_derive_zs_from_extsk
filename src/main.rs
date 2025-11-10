use std::env;

use ff::PrimeField;
use zcash_client_backend::{
    encoding::{
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
    },
    keys::sapling::ExtendedSpendingKey,
};
use zcash_primitives::{
    consensus::Network,
    constants,
};

/// Decode private key from hex string or base58 WIF format
fn decode_private_key(input_key: &str) -> Vec<u8> {
    if input_key.len() == 64 && input_key.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex format (64 hex characters = 32 bytes)
        hex::decode(input_key).expect("Invalid hex string for private key")
    } else {
        // Base58 format (private key)
        let decoded = bs58::decode(input_key)
            .into_vec()
            .expect("Invalid base58 string for private key");
        
        // Remove last 4 bytes (checksum) and take exactly 32 bytes from the end
        if decoded.len() < 36 {
            panic!("Decoded base58 key is too short (expected at least 36 bytes, got {})", decoded.len());
        }
        
        // Remove checksum (last 4 bytes) first
        let after_checksum = &decoded[..decoded.len() - 4];
        
        // Check minimum length: network_code (1) + privkey (32) + 0x01 (1) = 34 bytes
        if after_checksum.len() < 34 {
            panic!("Not a compressed WIF format (expected at least 34 bytes after checksum removal, got {})", after_checksum.len());
        }
        
        // Check if last byte is 0x01 (compressed address flag)
        let last_byte = after_checksum[after_checksum.len() - 1];
        if last_byte != 0x01 {
            panic!("Only compressed addresses are supported (last byte must be 0x01, got 0x{:02x})", last_byte);
        }
        
        // Remove the last byte (0x01) for compressed addresses
        let after_compressed_flag = &after_checksum[..after_checksum.len() - 1];
        
        // Take exactly the last 32 bytes from the end
        let without_checksum = &after_compressed_flag[after_compressed_flag.len() - 32..];
        
        without_checksum.to_vec()
    }
}

/// Derive ZS address from iguana_key and network
fn derive_zs_address(iguana_key: &[u8], net: Network) -> String {
    // Create ExtendedSpendingKey from iguana_key
    let extsk = ExtendedSpendingKey::master(iguana_key);

    // Derive Full Viewing Key from Spending Key
    let fvk = extsk.to_diversifiable_full_viewing_key();

    // Find first valid diversifier and address
    let (_diversifier_index, payment_address) = fvk.default_address();

    // Encode Sapling address (bech32 with prefix 'zs' for mainnet, 'ztestsapling' for testnet)
    let hrp = match net {
        Network::MainNetwork => "zs",
        Network::TestNetwork => "ztestsapling",
    };
    encode_payment_address(hrp, &payment_address)
}

fn main() {
    // ====== Input ======
    // 1st argument: private_key_hex (hex string, 64 characters) or wif_base58 (base58 WIF format)
    // 2nd argument (optional): "mainnet" | "testnet" (default is mainnet)
    let input_key = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("{} {} - (c) Decker, 2025", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        eprintln!("\x1b[33mUsage:\x1b[0m {} <private_key_hex|wif_base58> [mainnet|testnet]", env!("CARGO_PKG_NAME"));
        std::process::exit(1);
    });

    let net = match env::args().nth(2).as_deref() {
        Some("testnet") => Network::TestNetwork,
        _ => Network::MainNetwork,
    };

    // ====== Decode iguana_key from hex string or base58 private key ======
    let iguana_key = decode_private_key(&input_key);
    
    // Print debug info for base58 input (only in debug builds)
    if cfg!(debug_assertions) && (input_key.len() != 64 || !input_key.chars().all(|c| c.is_ascii_hexdigit())) {
        let decoded = bs58::decode(&input_key)
            .into_vec()
            .expect("Invalid base58 string for private key");
        let decoded_hex = hex::encode(&decoded);
        println!("Decoded base58 (hex): {}", decoded_hex);
        
        let after_checksum = &decoded[..decoded.len() - 4];
        let after_checksum_hex = hex::encode(after_checksum);
        println!("After checksum removed (hex): {}", after_checksum_hex);
        
        let without_checksum_hex = hex::encode(&iguana_key);
        println!("Without checksum (hex): {}", without_checksum_hex);
    }
    
    let iguana_key_hex = hex::encode(&iguana_key);

    // ====== Create ExtendedSpendingKey from iguana_key ======
    let extsk = ExtendedSpendingKey::master(&iguana_key);

    // ====== Extract all key component bytes ======
    // Get ask (SpendAuthorizingKey) - 32 bytes
    let expsk_bytes = extsk.expsk.to_bytes();
    let ask_bytes: [u8; 32] = expsk_bytes[0..32].try_into().unwrap();
    let ask_hex = hex::encode(ask_bytes);
    
    // Get nsk (Nullifier Secret Key) - 32 bytes from jubjub::Fr
    let nsk_repr = extsk.expsk.nsk.to_repr();
    let nsk_bytes: &[u8] = nsk_repr.as_ref();
    let nsk_hex = hex::encode(nsk_bytes);
    
    // Get ovk (Outgoing Viewing Key) - 32 bytes
    let ovk_bytes = extsk.expsk.ovk.0;
    let ovk_hex = hex::encode(ovk_bytes);
    
    // Get dk (Diversifier Key) - 32 bytes
    // Note: dk.0 is private, but we can access it through serialization
    // or use the fact that ExtendedSpendingKey has a write method
    // Let's serialize the whole key and extract dk from it
    let mut serialized = Vec::new();
    extsk.write(&mut serialized).unwrap();
    // Format: depth (1) + parent_fvk_tag (4) + child_index (4) + chain_code (32) + fvk (96) + dk (32)
    // dk is at offset: 1 + 4 + 4 + 32 + 96 = 137, length 32
    let dk_bytes: [u8; 32] = serialized[137..169].try_into().unwrap();
    let dk_hex = hex::encode(dk_bytes);

    // ====== Derive Full Viewing Key from Spending Key ======
    // ExtendedFullViewingKey for encoding (using deprecated method as it's needed for encoding)
    #[allow(deprecated)]
    let extfvk = extsk.to_extended_full_viewing_key();

    // ====== Encode Extended Full Viewing Key ======
    let hrp_extfvk = match net {
        Network::MainNetwork => constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        Network::TestNetwork => constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    };
    let extfvk_encoded = encode_extended_full_viewing_key(hrp_extfvk, &extfvk);

    // ====== Encode Sapling address ======
    let zs = derive_zs_address(&iguana_key, net);

    println!("Network:   {}", match net {
        Network::MainNetwork => "mainnet",
        Network::TestNetwork => "testnet",
    });
    // Yellow color for iguana_key label only
    println!("\x1b[33miguana_key (hex):\x1b[0m {}", iguana_key_hex);
    println!("ask (SpendAuthorizingKey): {}", ask_hex);
    println!("nsk (NullifierSecretKey):  {}", nsk_hex);
    println!("ovk (OutgoingViewingKey): {}", ovk_hex);
    println!("dk (DiversifierKey):       {}", dk_hex);
    // ====== Encode Extended Spending Key ======
    let hrp_extsk = match net {
        Network::MainNetwork => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        Network::TestNetwork => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    };
    let extsk_encoded = encode_extended_spending_key(hrp_extsk, &extsk);

    // Yellow color for Full Viewing Key and Extended Spending Key labels only
    println!("\x1b[33mFull Viewing Key:\x1b[0m {}", extfvk_encoded);
    println!("\x1b[33mExtended Spending Key:\x1b[0m {}", extsk_encoded);
    // Yellow color for ZS address label only
    println!("\x1b[33mZS address:\x1b[0m {}", zs);
}

#[cfg(test)]
mod tests {
    use zcash_primitives::zip32::ChildIndex;

    use super::*;

    #[test]
    fn test_wif_base58_to_zs_address() {
        let wif = "UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh";
        let expected_zs = "zs1vxr57r07tzsdhm0u26dcmrmpuck9kqjt7kd6l4wkanujx57qxfx4vwyj9dduepfal67axstl525";
        
        let iguana_key = decode_private_key(wif);
        let zs = derive_zs_address(&iguana_key, Network::MainNetwork);
        
        assert_eq!(zs, expected_zs);
    }

    #[test]
    fn test_hex_private_key_to_zs_address() {
        let hex_key = "907ece717a8f94e07de7bf6f8b3e9f91abb8858ebf831072cdbb9016ef53bc5d";
        let expected_zs = "zs1vxr57r07tzsdhm0u26dcmrmpuck9kqjt7kd6l4wkanujx57qxfx4vwyj9dduepfal67axstl525";
        
        let iguana_key = decode_private_key(hex_key);
        let zs = derive_zs_address(&iguana_key, Network::MainNetwork);
        
        assert_eq!(zs, expected_zs);
    }

    #[test]
    fn test_both_inputs_produce_same_iguana_key() {
        let wif = "UtrRXqvRFUAtCrCTRAHPH6yroQKUrrTJRmxt2h5U4QTUN1jCxTAh";
        let hex_key = "907ece717a8f94e07de7bf6f8b3e9f91abb8858ebf831072cdbb9016ef53bc5d";
        
        let iguana_key_from_wif = decode_private_key(wif);
        let iguana_key_from_hex = decode_private_key(hex_key);
        
        assert_eq!(iguana_key_from_wif, iguana_key_from_hex);
    }

    #[test]
    fn test_wif_base58_to_zs_address_second() {
        let wif = "UvzEP1WnYeAQqPn9oknCEcUEdGp1vNamcNdXbsNqFD9S6rYkcnsA";
        let expected_zs = "zs134h6huury9slt4mce4rglu6y6p6h30m6zd52pslnewcwv5fuhjyt9c5rjyhncrx565tc2lqyjyy";
        
        let iguana_key = decode_private_key(wif);
        let zs = derive_zs_address(&iguana_key, Network::MainNetwork);
        
        assert_eq!(zs, expected_zs);
    }

    #[test]
    fn test_hex_private_key_to_zs_address_second() {
        let hex_key = "d02fccadf560a697f2f3671bd667df1d328b705f87ad787193fff7366b8c8546";
        let expected_zs = "zs134h6huury9slt4mce4rglu6y6p6h30m6zd52pslnewcwv5fuhjyt9c5rjyhncrx565tc2lqyjyy";
        
        let iguana_key = decode_private_key(hex_key);
        let zs = derive_zs_address(&iguana_key, Network::MainNetwork);
        
        assert_eq!(zs, expected_zs);
    }

    #[test]
    fn test_both_inputs_produce_same_iguana_key_second() {
        let wif = "UvzEP1WnYeAQqPn9oknCEcUEdGp1vNamcNdXbsNqFD9S6rYkcnsA";
        let hex_key = "d02fccadf560a697f2f3671bd667df1d328b705f87ad787193fff7366b8c8546";
        
        let iguana_key_from_wif = decode_private_key(wif);
        let iguana_key_from_hex = decode_private_key(hex_key);
        
        assert_eq!(iguana_key_from_wif, iguana_key_from_hex);
    }

    #[test]
    fn test_hd_derivation() {
        // BIP39 seed in hex format (128 hex characters = 64 bytes)
        let bip39_seed_hex = "e2881cf895a7adaa27bbe8ad5e1db2d1c654d8007f58b7828386eb05666a6ec512d1d8ba98d5d299cce1cf8fdbeb38ae6e7bdad4bb7b965715aeaf5af6d7df6c";
        
        // Decode hex seed to bytes
        let bip39_seed = hex::decode(bip39_seed_hex).expect("Invalid hex string for BIP39 seed");
        
        // Create master key from BIP39 seed
        let extsk_master = ExtendedSpendingKey::master(&bip39_seed);
        
        // Derive child key at path "m/32'/141'/0'"
        let derivation_path = [ChildIndex::hardened(32), ChildIndex::hardened(141), ChildIndex::hardened(0)];
        
        let extsk = ExtendedSpendingKey::from_path(&extsk_master, &derivation_path);
        
        // Get Full Viewing Key and derive address
        let fvk = extsk.to_diversifiable_full_viewing_key();
        let (_diversifier_index, payment_address) = fvk.default_address();
        
        // Encode Sapling address
        let hrp = "zs"; // mainnet
        let zs_address = encode_payment_address(hrp, &payment_address);
        
        // Verify the expected ZS address
        let expected_zs = "zs10zumm23c5q6fn8qf60v022kfxdfyunxpnya2ezmextu0ups4qvfdnmssmfeuwy3vcesx224x0st";
        assert_eq!(zs_address, expected_zs);
    }
}
