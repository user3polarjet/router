use base64::Engine;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::Digest;
use rand::RngCore;

const RSA_CHUNK: usize = 53;

pub struct AesSession {
    pub key: String,
    pub iv: String,
}

pub fn new_aes_session() -> AesSession {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    AesSession {
        key: hex::encode(&bytes[..8]),
        iv: hex::encode(&bytes[8..]),
    }
}

pub fn aes_encrypt(session: &AesSession, plain: &str) -> anyhow::Result<String> {
    let cipher = cbc::Encryptor::<aes::Aes128>::new_from_slices(session.key.as_bytes(), session.iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes init: {e}"))?;
    let encrypted = cipher.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plain.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
}

pub fn aes_decrypt(session: &AesSession, encoded: &str) -> anyhow::Result<String> {
    let raw = base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
    let cipher = cbc::Decryptor::<aes::Aes128>::new_from_slices(session.key.as_bytes(), session.iv.as_bytes())
        .map_err(|e| anyhow::anyhow!("aes init: {e}"))?;
    let mut plain = cipher
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&raw)
        .map_err(|e| anyhow::anyhow!("aes decrypt: {e}"))?;
    if let Some(&pad) = plain.last() {
        let keep = plain.len().saturating_sub(pad as usize);
        plain.truncate(keep);
    }
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

pub fn rsa_public_key(modulus_hex: &str, exponent_hex: &str) -> anyhow::Result<rsa::RsaPublicKey> {
    let n = rsa::BigUint::parse_bytes(modulus_hex.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid RSA modulus: {modulus_hex}"))?;
    let e = rsa::BigUint::parse_bytes(exponent_hex.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid RSA exponent: {exponent_hex}"))?;
    Ok(rsa::RsaPublicKey::new(n, e)?)
}

pub fn rsa_encrypt_hex(key: &rsa::RsaPublicKey, data: &[u8]) -> anyhow::Result<String> {
    let encrypted = key.encrypt(&mut rand::rngs::OsRng, rsa::Pkcs1v15Encrypt, data)?;
    Ok(hex::encode(encrypted))
}

pub fn credentials_hash(username: &str, password: &str) -> String {
    hex::encode(md5::Md5::digest(format!("{username}{password}").as_bytes()))
}

pub fn signature(
    session: &AesSession,
    key: &rsa::RsaPublicKey,
    hash: &str,
    seq: u64,
    is_login: bool,
) -> anyhow::Result<String> {
    let plain = if is_login {
        format!("k={}&i={}&h={}&s={}", session.key, session.iv, hash, seq)
    } else {
        format!("h={hash}&s={seq}")
    };
    let mut sign = String::new();
    for chunk in plain.as_bytes().chunks(RSA_CHUNK) {
        sign.push_str(&rsa_encrypt_hex(key, chunk)?);
    }
    Ok(sign)
}
