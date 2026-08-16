use std::print;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce}; // Or `Aes128Gcm`
// use base64::{engine::general_purpose, Engine as _};
use base64::engine::general_purpose::{STANDARD,STANDARD_NO_PAD, URL_SAFE_NO_PAD,URL_SAFE};
use base64::Engine;
use bcrypt::{hash, verify, DEFAULT_COST};
use des::cipher::{BlockDecrypt, BlockEncrypt};  // 通过 des 重新导出
use des::cipher::crypto_common::generic_array::GenericArray;
// use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit as CipherKeyInit};
// use cipher::block_padding::NoPadding;
use des::Des;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use openssl::sign::Verifier;
use ecb::{Encryptor, Decryptor};
// use cipher::crypto_common::generic_array::GenericArray;

// 定义 DES-ECB 加密器和解密器别名
type DesEcbEnc = Encryptor<Des>;
type DesEcbDec = Decryptor<Des>;

/// 支持的填充方式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PaddingType {
    /// 0x80 后跟 0x00（dart_des 的 OneAndZeroes）
    OneAndZeroes,
    /// PKCS7 / PKCS5（末尾补 N 个 N）
    Pkcs7,
}

pub enum UuidFormat {
    Normal,
    NoUnderline,
    NoUnderlineUpperCase,
}

/*
des加密解密,这里的加密解密是和dart端的dart_des库配套使用的,所以加密解密的结果是一样的
*/
/// des加密
pub fn jiami(mingwen: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 中间层改用 STANDARD（带 = padding），与 Dart 端 WDEncrypt.encodeUseBase64UrlSafe 的实际输出对齐
    let base64_guard = STANDARD.encode(mingwen.as_bytes());
    let key_bytes = normalize_key(key);
    let encrypted = des_ecb_encrypt(base64_guard.as_bytes(), &key_bytes)?;
    let miwen = STANDARD_NO_PAD.encode(&encrypted);
    Ok(miwen)
}
/// des解密
pub fn jiemi(miwen: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 将base64编码的字符串还原为密文字节数组
    let encrypted_bytes = decode_base64(miwen)?;
    // 将key强制设置为8字节长度
    let key_bytes = normalize_key(key);
    // 使用des_ecb_decrypt函数进行解密,得到明文base64编码的字节数组
    let decrypted_bytes = des_ecb_decrypt(&encrypted_bytes, &key_bytes)?;
    //  将明文base64编码的字节数组转换为base64字符串
    let mingwen_base64 = String::from_utf8(decrypted_bytes)?;
    //  将base64字符串还原为明文字节数组
    let mingwen_bytes = decode_base64(&mingwen_base64)?;
    //  将明文字节数组转换为明文字符串
    let mingwen = String::from_utf8(mingwen_bytes)?;
    Ok(mingwen)
}



/// 把 key强制设置为 8 字节长度
fn normalize_key(key: &str) -> [u8; 8] {
    let bytes = key.as_bytes();
    let mut result = [0u8; 8];
    let len = bytes.len().min(8);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

/// base64 解码
fn decode_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
}
/// des加密实现
fn des_ecb_encrypt(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_array = GenericArray::from_slice(key);
    let cipher = Des::new(key_array);
    const BLOCK_SIZE: usize = 8;

    // OneAndZeroes 填充：先写 0x80，再补 0x00 到 8 的倍数
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % BLOCK_SIZE != 0 {
        padded.push(0x00);
    }

    let mut result = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    Ok(result)
}

// /// des解密实现
fn des_ecb_decrypt(data: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() % 8 != 0 {
        return Err("密文长度必须是 8 的倍数".into());
    }
    let key_array = GenericArray::from_slice(key);
    let cipher = Des::new(key_array);

    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        result.extend_from_slice(&block);
    }

    // 去除 OneAndZeroes 填充
    if let Some(pos) = result.iter().rposition(|&b| b == 0x80) {
        let all_zeros = result[pos + 1..].iter().all(|&b| b == 0x00);
        if all_zeros {
            result.truncate(pos);
            return Ok(result);
        }
    }
    Ok(result)
}

//===============================

/// rsa算法,公钥加密
pub fn encrypt_use_rsa(plain_text: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::public_key_from_pem(public_key)?; // 加载公钥
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.public_encrypt(plain_text, &mut buf, Padding::PKCS1)?;
    buf.truncate(len); // 截断多余的部分
    Ok(buf.to_vec())
}

/// rsa算法,私钥解密
pub fn decrypt_use_rsa(cipher_text: &[u8], private_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::private_key_from_pem(private_key)?; // 加载私钥
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.private_decrypt(cipher_text, &mut buf, Padding::PKCS1)?;
    buf.truncate(len); // 截断多余的部分
    Ok(buf.to_vec())
}

/// rsa算法私钥签名
pub fn sign_rsa(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::private_key_from_pem(private_key)?; // 加载私钥
    let pkey = PKey::from_rsa(rsa)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(message)?;
    let signature = signer.sign_to_vec()?;
    Ok(signature)
}

/// rsa算法,公钥验证签名
pub fn verify_rsa(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, ErrorStack> {
    let rsa = Rsa::public_key_from_pem(public_key)?; // 加载公钥
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
    STANDARD.encode(bytes)
}

/// 解密 Base64 字符串
pub fn decrypt_use_base64(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decoded_bytes = STANDARD.decode(input)?;
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
pub fn encrypt_use_aes(key: &str, iv: &str, plain_text: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv.as_bytes());
    let ciphertext = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .expect("encryption failure");
    encrypt_use_base64(ciphertext)
}

/// 这里是和本库的encrypt_use_aes方法配套使用的,原本想让传进来的加密字符串是base64加密后的
/// 但为了更通用一些,所以这里还是用Vec<u8>传进来
/// 所以如果密文是用本库的encrypt_use_aes加密的,那么自行用本库的decrypt_use_base64方法解密
/// 为Vec<u8>再传进来,decrypt_use_base64解密默认返回的就是Vec<u8>
pub fn decrypt_use_aes(key: &str, iv: &str, cipher_text: &Vec<u8>) -> String {
    let key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv.as_bytes());
    let decrypted_text = cipher
        .decrypt(nonce, cipher_text.as_ref())
        .expect("decryption failure");
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
        UuidFormat::NoUnderlineUpperCase => uuid::Uuid::new_v4()
            .to_string()
            .replace("-", "")
            .to_uppercase(),
    }
}
