use sn_cryptography::cryptography::*;

#[test]
fn test_generate_seed_thread() {
    let seed = generate_seed_thread();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_generate_seed_os() {
    let seed = generate_seed_os();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_inherit_seed() {
    let seed = inherit_seed();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_generate_keypair() {
    let keypair = Keypair::generate_keypair();
    assert_eq!(keypair.private.to_bytes().len(), 32);
    assert_eq!(keypair.public.to_bytes().len(), 32);
}

#[test]
fn test_sign_and_verify() {
    let message = b"Hello, world!";
    let keypair = Keypair::generate_keypair();
    let signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature));
}

#[test]
fn test_sign_and_verify_different_way() {
    let keypair = Keypair::generate_keypair();
    let message = "Hello, world!".as_bytes();

    let signature = keypair.sign(&message);

    println!("message: {:?}", message);
    println!("public key: {:?}", keypair.public.as_bytes());
    println!("signature: {:?}", signature.signature.to_bytes());

    assert!(keypair.verify(&message, &signature));
}

#[test]
fn test_derive_address() {
    let keypair = Keypair::generate_keypair();
    let address = keypair.derive_address();
    assert_eq!(address.address.len(), 20);
}

#[test]
fn test_address_to_string() {
    let address = Address::from_bytes([
        119, 2, 129, 224, 245, 161, 44, 24, 46, 93, 89, 87, 144, 63, 53, 63, 33, 64, 92, 127,
    ]);
    assert_eq!(
        address.to_string(),
        "770281e0f5a12c182e5d5957903f353f21405c7f"
    );
}

#[test]
fn test_address_from_bytes() {
    let bytes = [
        119, 2, 129, 224, 245, 161, 44, 24, 46, 93, 89, 87, 144, 63, 53, 63, 33, 64, 92, 127,
    ];
    let address = Address::from_bytes(bytes);
    assert_eq!(address.address, bytes);
}
