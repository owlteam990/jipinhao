# CryptoJS 旧版钱包生成实验

使用 `crypto-js@3.1.9-1` 的 `CryptoJS.lib.WordArray.random(32)` 生成私钥，
再通过 ethers 离线派生以太坊/EVM 公钥和地址，不生成助记词。

**旧版随机数不具备密码学安全性。仅用于实验，请勿存入真实资产。**
程序会在终端输出明文私钥，请勿分享输出。

## 运行

```bash
npm install
npm start
```

## 参考

- [CryptoJS 官方安全公告](https://github.com/brix/crypto-js/security/advisories/GHSA-rg76-677x-56q9)
- [ethers Wallet 文档](https://docs.ethers.org/v6/api/wallet/)
