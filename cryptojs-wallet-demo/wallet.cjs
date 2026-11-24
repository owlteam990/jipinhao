const CryptoJS = require("crypto-js");
const { Wallet } = require("ethers");

// secp256k1 曲线阶：私钥必须满足 1 <= key < N。
const N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

function generateWallet() {
  let hex;
  let value;

  do {
    // 实验用途：旧版随机数不具备密码学安全性。
    hex = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);
    value = BigInt(`0x${hex}`);
  } while (value === 0n || value >= N);

  const wallet = new Wallet(`0x${hex}`);
  return {
    privateKey: wallet.privateKey,
    publicKey: wallet.signingKey.publicKey,
    address: wallet.address,
  };
}

if (require.main === module) {
  console.error("实验用途：旧版随机数不安全，请勿向生成地址转入资产。");
  console.log(JSON.stringify(generateWallet(), null, 2));
}

module.exports = { generateWallet };
