#![feature(core_intrinsics)]

extern crate hmac;
extern crate sha2;
extern crate hex;

use sha2::Sha256;
use hmac::{Hmac, Mac};
use hex::encode;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;


fn print_type_of<T>(_: &T) {
    println!("{}", unsafe { std::intrinsics::type_name::<T>() });
}

fn main() {
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    println!("new key: {:?}", mac);
    print_type_of(&mac);

    mac.input(b"input message");
    println!("key+msg: {:?}", mac);
    print_type_of(&mac);

    // `result` has type `MacResult` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.result();
    print_type_of(&result);
   // println!("result: {:?}", result);
    // To get underlying array use `code` method, but be carefull, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `MacResult`
    let code_bytes = result.code();
    let code = hex::encode(code_bytes);

    assert_eq!(code.to_string(), String::from("97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9"));

    println!("{:?}", code);
    print_type_of(&code_bytes);
    println!("code_bytes: {:?}", code_bytes);
    let mut mac = HmacSha256::new_varkey(b"my secret and secure key")
        .expect("HMAC can take key of any size");

    mac.input(b"input message");

    // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    let a = mac.verify(&code_bytes).unwrap();
    
    println!("Hello, world!{:?}", a);
    print_type_of(&a)
}




/*

Finished dev [unoptimized + debuginfo] target(s) in 3.49s
     Running `target/debug/hmac`
new key: Hmac { digest: Sha256 { ... }, i_key_pad: [91, 79, 22, 69, 83, 85, 68, 83, 66, 22, 87, 88, 82, 22, 69, 83, 85, 67, 68, 83, 22, 93, 83, 79, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54], opad_digest: Sha256 { ... } }
hmac::Hmac<sha2::sha256::Sha256>
key+msg: Hmac { digest: Sha256 { ... }, i_key_pad: [91, 79, 22, 69, 83, 85, 68, 83, 66, 22, 87, 88, 82, 22, 69, 83, 85, 67, 68, 83, 22, 93, 83, 79, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54], opad_digest: Sha256 { ... } }
hmac::Hmac<sha2::sha256::Sha256>
crypto_mac::MacResult<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>
"97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9"
generic_array::GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>
code_bytes: [151, 210, 165, 105, 5, 155, 188, 216, 234, 212, 68, 79, 249, 144, 113, 244, 192, 29, 0, 91, 206, 254, 13, 53, 103, 225, 190, 98, 142, 95, 220, 217]
Hello, world!()
()

*/
