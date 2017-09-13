use openssl::rsa::{Rsa, PKCS1_PADDING};
use openssl::symm::{self, Cipher};

pub fn decrypt(rsa: &Rsa,
        size_rsa: usize,
        input: &[u8]
    ) -> Result<::common::Packet, Box<::std::error::Error>> {

    println!("Raw: {:?}", input);

    let mut keyiv = vec![0; size_rsa];
    rsa.private_decrypt(&input[..size_rsa], &mut keyiv, PKCS1_PADDING)?;
    keyiv.truncate(32+16);

    println!("Decrypted keyiv: {:?}", keyiv);

    let (key, iv) = keyiv.split_at(32);
    let decrypted = symm::decrypt(Cipher::aes_256_cbc(), key, Some(iv), &input[size_rsa..])?;

    println!("Decrypted: {:?}", decrypted);

    Ok(::common::deserialize(&decrypted)?)
}
