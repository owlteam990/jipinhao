//! TRON 地址推导：私钥 → secp256k1 公钥 → Keccak-256 → Base58Check

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// TRON 主网地址版本前缀
pub const TRON_ADDRESS_PREFIX: u8 = 0x41;

/// 由私钥推导 TRON 主网地址与未压缩公钥摘要信息
///
/// # Arguments
/// * `secp` - secp256k1 上下文（线程内复用）
/// * `secret_key` - 32 字节私钥
///
/// # Returns
/// Base58Check 编码的 T 开头地址
pub fn private_key_to_address(secp: &Secp256k1<secp256k1::All>, secret_key: &SecretKey) -> String {
    // 1. 椭圆曲线乘点得到未压缩公钥（65 字节，首字节 0x04）
    let public_key = PublicKey::from_secret_key(secp, secret_key);
    let uncompressed = public_key.serialize_uncompressed();

    // 2. 对去前缀后的 64 字节公钥做 Keccak-256
    let hash = Keccak256::digest(&uncompressed[1..]);

    // 3. 0x41 + 哈希后 20 字节，得到 21 字节裸地址
    let mut payload = [0u8; 25];
    payload[0] = TRON_ADDRESS_PREFIX;
    payload[1..21].copy_from_slice(&hash[12..32]);

    // 4. 双 SHA-256 取前 4 字节作为校验和
    let checksum = double_sha256(&payload[..21]);
    payload[21..25].copy_from_slice(&checksum[..4]);

    // 5. Base58 编码
    bs58::encode(payload).into_string()
}

/// 对数据做双 SHA-256
///
/// # Arguments
/// * `data` - 待哈希数据
///
/// # Returns
/// 32 字节摘要
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// 校验：私钥十六进制 → 地址，用于命中后二次确认
///
/// # Arguments
/// * `private_key_hex` - 64 位十六进制私钥
///
/// # Returns
/// 推导出的 TRON 地址；私钥非法时返回 None
pub fn address_from_hex(private_key_hex: &str) -> Option<String> {
    let bytes = hex::decode(private_key_hex).ok()?;
    let secret_key = SecretKey::from_slice(&bytes).ok()?;
    let secp = Secp256k1::new();
    Some(private_key_to_address(&secp, &secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;

    #[test]
    fn generated_address_starts_with_t() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut OsRng);
        let address = private_key_to_address(&secp, &secret_key);
        assert!(address.starts_with('T'));
        assert!(address.len() >= 34);
    }

    #[test]
    fn known_key_roundtrip() {
        // 固定私钥自洽：推导地址后再用同一私钥重算应一致
        let hex_key = "0000000000000000000000000000000000000000000000000000000000000001";
        let addr1 = address_from_hex(hex_key).expect("valid key");
        let addr2 = address_from_hex(hex_key).expect("valid key");
        assert_eq!(addr1, addr2);
        assert!(addr1.starts_with('T'));
    }
}
