use hex;
use std::str;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() {
    let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let raw_bytes: Vec<u8> = hex::decode(input).unwrap();

    // https://stackoverflow.com/a/19076878. Note, Vec coerces to slices and other juicy tidbits.
    let m: &str = str::from_utf8(&raw_bytes).unwrap();
    println!("{:?}", m);

    let b64: String = STANDARD.encode(raw_bytes);
    println!("{}", b64);
}
