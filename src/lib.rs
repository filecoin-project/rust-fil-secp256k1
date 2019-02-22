use libc;
use rand::OsRng;
use secp256k1::{constants, SecretKey};
use std::boxed::Box;
// use std::slice::from_raw_parts;

// TODO: Investigate setting up the context for faster operations.

const SECRET_KEY_SIZE: usize = constants::SECRET_KEY_SIZE;

#[no_mangle]
pub unsafe extern "C" fn generate_key() -> *mut GenerateKeyResponse {
    let mut rng = OsRng::new().expect("No valid cryptographic source available");
    let key = SecretKey::new(&mut rng);

    let response = GenerateKeyResponse { key: key.into() };

    Box::into_raw(Box::new(response))
}

#[repr(C)]
pub struct GenerateKeyResponse {
    pub key: [u8; SECRET_KEY_SIZE],
}

#[no_mangle]
pub unsafe extern "C" fn destroy_generate_key_response(ptr: *mut GenerateKeyResponse) {
    let _ = Box::from_raw(ptr);
}

#[cfg(test)]
mod tests {
    #[test]
    fn sign() {
        use rand::OsRng;
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

        let sig = secp.sign(&message, &secret_key);
        assert!(secp.verify(&message, &sig, &public_key).is_ok());
    }
}
