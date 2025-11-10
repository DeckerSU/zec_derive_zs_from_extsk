use std::{env, io::Write};

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
    // 1st argument: iguana_key (hex string, 64 characters)
    // 2nd argument (optional): "mainnet" | "testnet" (default is mainnet)
    let iguana_key_hex = env::args().nth(1).expect(
        "Usage: zec_derive_zs_from_extsk <iguana_key_hex> [mainnet|testnet]",
    );

    let net = match env::args().nth(2).as_deref() {
        Some("testnet") => Network::TestNetwork,
        _ => Network::MainNetwork,
    };

    // ====== Decode iguana_key from hex string ======
    let iguana_key: Vec<u8> = hex::decode(&iguana_key_hex)
        .expect("Invalid hex string for iguana_key");

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
    // ExtendedFullViewingKey for encoding
    let extfvk = extsk.to_extended_full_viewing_key();
    // DiversifiableFullViewingKey for address generation
    let fvk = extsk.to_diversifiable_full_viewing_key();

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
    println!("iguana_key (hex): {}", iguana_key_hex);
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

    println!("Full Viewing Key: {}", extfvk_encoded);
    println!("Extended Spending Key: {}", extsk_encoded);
    // Yellow color for ZS address: \x1b[33m for yellow, \x1b[0m to reset
    println!("\x1b[33mZS address: {}\x1b[0m", zs);
}
