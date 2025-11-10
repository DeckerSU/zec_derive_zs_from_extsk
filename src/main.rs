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

fn main() {
    // ====== Input ======
    // 1st argument: private_key_hex (hex string, 64 characters) or wif_base58 (base58 WIF format)
    // 2nd argument (optional): "mainnet" | "testnet" (default is mainnet)
    let input_key = env::args().nth(1).expect(
        "Usage: zec_derive_zs_from_extsk <private_key_hex|wif_base58> [mainnet|testnet]",
    );

    let net = match env::args().nth(2).as_deref() {
        Some("testnet") => Network::TestNetwork,
        _ => Network::MainNetwork,
    };

    // ====== Decode iguana_key from hex string or base58 private key ======
    let iguana_key: Vec<u8> = if input_key.len() == 64 && input_key.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex format (64 hex characters = 32 bytes)
        hex::decode(&input_key)
            .expect("Invalid hex string for iguana_key")
    } else {
        // Base58 format (private key)
        let decoded = bs58::decode(&input_key)
            .into_vec()
            .expect("Invalid base58 string for private key");
        
        // Print decoded bytes in hex
        let decoded_hex = hex::encode(&decoded);
        println!("Decoded base58 (hex): {}", decoded_hex);
        
        // Remove last 4 bytes (checksum) and take exactly 32 bytes from the end
        if decoded.len() < 36 {
            panic!("Decoded base58 key is too short (expected at least 36 bytes, got {})", decoded.len());
        }
        
        // Remove checksum (last 4 bytes) first
        let after_checksum = &decoded[..decoded.len() - 4];
        
        // Print after_checksum in hex
        let after_checksum_hex = hex::encode(after_checksum);
        println!("After checksum removed (hex): {}", after_checksum_hex);
        
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
        
        // Take exactly the last 32 bytes from the end as without_checksum
        let without_checksum = &after_compressed_flag[after_compressed_flag.len() - 32..];
        
        // Print without_checksum in hex (exactly 32 bytes)
        let without_checksum_hex = hex::encode(without_checksum);
        println!("Without checksum (hex): {}", without_checksum_hex);
        
        without_checksum.to_vec()
    };
    
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
    // DiversifiableFullViewingKey for address generation
    let fvk = extsk.to_diversifiable_full_viewing_key();
    // ExtendedFullViewingKey for encoding (using deprecated method as it's needed for encoding)
    #[allow(deprecated)]
    let extfvk = extsk.to_extended_full_viewing_key();

    // ====== Find first valid diversifier and address ======
    // default_address() will find the first valid diversifier and return PaymentAddress
    let (_diversifier_index, payment_address) = fvk.default_address();

    // ====== Encode Extended Full Viewing Key ======
    let hrp_extfvk = match net {
        Network::MainNetwork => constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        Network::TestNetwork => constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    };
    let extfvk_encoded = encode_extended_full_viewing_key(hrp_extfvk, &extfvk);

    // ====== Encode Sapling address (bech32 with prefix 'zs' for mainnet, 'ztestsapling' for testnet) ======
    let hrp = match net {
        Network::MainNetwork => "zs",
        Network::TestNetwork => "ztestsapling",
    };
    let zs = encode_payment_address(hrp, &payment_address);

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
