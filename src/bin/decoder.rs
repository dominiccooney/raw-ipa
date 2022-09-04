use base64;
use hpke;
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use pem;
use std::fs;
use std::iter::zip;
use std::path::PathBuf;
use structopt::StructOpt;
//use x25519_dalek;

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(help = "Context for the shares (.info)")]
    info: String,
    #[structopt(required = true, help = "Path to helper private key PEM files")]
    keys: Vec<PathBuf>,
    #[structopt(required = true, last = true, help = "Encrypted secret shares")]
    shares: Vec<String>,
}

fn load_key(path: &PathBuf) -> <X25519HkdfSha256 as Kem>::PrivateKey {
    let pem_content = fs::read(path).unwrap();
    let key = pem::parse(pem_content).unwrap();
    assert_eq!("PRIVATE KEY", key.tag);

    assert_eq!(48, key.contents.len());
    // ASN1 preamble of X25519 private key certificate.
    assert_eq!(
        [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32],
        key.contents[0..16]
    );
    <<X25519HkdfSha256 as Kem>::PrivateKey as hpke::Deserializable>::from_bytes(&key.contents[16..])
        .unwrap()
}

type KeyShare = (<X25519HkdfSha256 as Kem>::PrivateKey, Vec<u8>);

fn decrypter(info: Vec<u8>) -> impl Fn(u64, KeyShare) -> u64 {
    move |id: u64, key_share: KeyShare| -> u64 {
        let encapsulated_key_length = 32;
        let enc = <<X25519HkdfSha256 as Kem>::EncappedKey as hpke::Deserializable>::from_bytes(
            &key_share.1[0..encapsulated_key_length],
        )
        .expect("could not decode encapsulated key");
        let mut decryption_context = hpke::setup_receiver::<
            hpke::aead::AesGcm256,
            hpke::kdf::HkdfSha256,
            X25519HkdfSha256,
        >(&hpke::OpModeR::Base, &key_share.0, &enc, &info)
        .expect("failed to set up receiver");
        let plaintext = decryption_context
            .open(&key_share.1[encapsulated_key_length..], &[])
            .expect("invalid ciphertext");
        let mask = u64::from_le_bytes(plaintext.try_into().expect("plaintext should be 8 bytes"));
        println!("id={:016x} mask={:016x} out={:016x}", id, mask, id ^ mask);
        id ^ mask
    }
}

fn main() {
    let args = Args::from_args();
    if args.keys.len() != args.shares.len() {
        eprintln!("you must specify as many helper keys as shares");
    }
    let info = base64::decode(args.info).unwrap();
    let shares = args.shares.iter().map(|s| base64::decode(s).unwrap());
    let id = zip(args.keys.iter().map(load_key), shares).fold(0, decrypter(info));
    println!("id:{}", id);
}
