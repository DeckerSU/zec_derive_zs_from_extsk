use std::env;

use zcash_client_backend::encoding::{
    decode_extended_spending_key, encode_extended_full_viewing_key, encode_payment_address,
};
use zcash_primitives::{
    consensus::Network,
    constants,
};

fn main() {
    // ====== Input ======
    // 1st argument: secret-extended-key (string like
    // "secret-extended-key-main1..." for mainnet or "...-test1..." for testnet)
    // 2nd argument (optional): "mainnet" | "testnet" (default is mainnet)
    let extsk_str = env::args().nth(1).expect(
        "Usage: zec_derive_zs_from_extsk <secret-extended-key> [mainnet|testnet]",
    );

    let net = match env::args().nth(2).as_deref() {
        Some("testnet") => Network::TestNetwork,
        _ => Network::MainNetwork,
    };

    // ====== Decode EXTSK from human-readable string ======
    // Returns ExtendedSpendingKey for the specified network
    let hrp_extsk = match net {
        Network::MainNetwork => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        Network::TestNetwork => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    };
    let extsk = decode_extended_spending_key(hrp_extsk, &extsk_str)
        .expect("Invalid secret-extended-key for the selected network");

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
    println!("Full Viewing Key: {}", extfvk_encoded);
    println!("ZS address: {}", zs);
}
