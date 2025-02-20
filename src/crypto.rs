use openssl::rsa::{Rsa, Padding};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use base64::{engine::general_purpose, Engine as _};
use bcrypt::{DEFAULT_COST, hash, verify};


/// rsa算法,公钥加密
pub fn encrypt_use_rsa(plain_text: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::public_key_from_pem(public_key)?;  // 加载公钥
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.public_encrypt(plain_text, &mut buf, Padding::PKCS1)?;
    buf.truncate(len); // 截断多余的部分
    Ok(buf)
}


/// rsa算法,私钥解密
pub fn decrypt_use_rsa(cipher_text: &[u8], private_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::private_key_from_pem(private_key)?;  // 加载私钥
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.private_decrypt(cipher_text, &mut buf, Padding::PKCS1)?;
    buf.truncate(len); // 截断多余的部分
    Ok(buf)
}


/// rsa算法私钥签名
pub fn sign_rsa(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::private_key_from_pem(private_key)?;  // 加载私钥
    let pkey = PKey::from_rsa(rsa)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(message)?;
    let signature = signer.sign_to_vec()?;
    Ok(signature)
}


/// rsa算法,公钥验证签名
pub fn verify_rsa(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, ErrorStack> {
    let rsa = Rsa::public_key_from_pem(public_key)?;  // 加载公钥
    let pkey = PKey::from_rsa(rsa)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(message)?;
    let is_valid = verifier.verify(&signature)?;
    Ok(is_valid)
}


/// 字符串加密为 Base64 
// 函数接收一个泛型参数 T,它实现了 AsRef<[u8]> trait
// AsRef<[u8]>这个trait的意思就是需要实现了as_ref这个方法，返回一个Vec<u8>数组
// &str,Vec<u8>,String都实现了这个trait
pub fn encrypt_use_base64<T: AsRef<[u8]>>(input: T) -> String {
   let bytes = input.as_ref();
   general_purpose::STANDARD.encode(bytes)
}

/// 解密 Base64 字符串
pub fn decrypt_use_base64(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decoded_bytes = general_purpose::STANDARD.decode(input)?;
    Ok(decoded_bytes)
}

/// 用bcrypt加密
pub fn encrypt_use_bcrypt(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

/// 验证bcrypt密码
pub fn verify_use_bcrypt(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}
