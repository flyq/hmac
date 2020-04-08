extern crate hmac;
extern crate sha2;

use sha2::Sha256;
use hmac::{Hmac, Mac};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn main() {
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    println!("new key: {:?}", mac);

    mac.input(b"input message");
    println!("key+msg: {:?}", mac);

    // `result` has type `MacResult` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.result();
   // println!("result: {:?}", result);
    // To get underlying array use `code` method, but be carefull, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `MacResult`
    let code_bytes = result.code();
    println!("code_bytes: {:?}", code_bytes);
    let mut mac = HmacSha256::new_varkey(b"my secret and secure key")
        .expect("HMAC can take key of any size");

    mac.input(b"input message");

    // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    let a = mac.verify(&code_bytes).unwrap();
    
    println!("Hello, world!{:?}", a);
}
