use openssl::rsa::{Rsa, Padding};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use base64::{engine::general_purpose, Engine as _};
use bcrypt::{DEFAULT_COST, hash, verify};

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::Aead;

pub enum UuidFormat {
    Normal,
    NoUnderline,
    NoUnderlineUpperCase
}

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

/// 因为加密后的结果是字节数组,不好查看,所以这里先转成base64(还能支持中文)
/// 主要,key的长度是32字节,需要"abcdabcdabcdabcdabcdabcdabcdabcd"这样有32个字符的符串才行
/// iv的长度是12字节,"abcdabcdabcd"类似这样
pub fn encrypt_use_aes(key:&str,iv:&str,plain_text:&str)->String{
    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv.as_bytes());
    let ciphertext = cipher.encrypt(nonce, plain_text.as_bytes()).expect("encryption failure");
    encrypt_use_base64(ciphertext)
}

/// 这里是和本库的encrypt_use_aes方法配套使用的,原本想让传进来的加密字符串是base64加密后的
/// 但为了更通用一些,所以这里还是用Vec<u8>传进来
/// 所以如果密文是用本库的encrypt_use_aes加密的,那么自行用本库的decrypt_use_base64方法解密
/// 为Vec<u8>再传进来,decrypt_use_base64解密默认返回的就是Vec<u8>
pub fn decrypt_use_aes(key:&str,iv:&str,cipher_text:&Vec<u8>)-> String{
    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv.as_bytes()); 
    let decrypted_text = cipher.decrypt(nonce, cipher_text.as_ref()).expect("decryption failure");
    String::from_utf8_lossy(&decrypted_text).to_string()
}

/// 生成uuid
/// 格式有三种,普通格式,没有下划线,没有下划线大写
/// 生成正常格式的uuid:"f00edb48-96a3-4e39-a78f-e62dc99a02eb"
/// 生成没有下划线的uuid:"dced1b6c9a3944eb82e94c629eaf6ef8"
/// 生成没有下划线大写的uuid:"D3AB50A7D5F24203818DE9B495D907E8"
pub fn obtain_uuid(format: UuidFormat) -> String {
    match format {
        UuidFormat::Normal => uuid::Uuid::new_v4().to_string(),
        UuidFormat::NoUnderline => uuid::Uuid::new_v4().to_string().replace("-", ""),
        UuidFormat::NoUnderlineUpperCase => uuid::Uuid::new_v4().to_string().replace("-", "").to_uppercase()
    }
}