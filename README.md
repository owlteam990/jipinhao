# TRON 极品号碰撞器

本地暴力搜索带吉利后缀的 TRON 地址。地址**不是链上铸造**，而是随机私钥经椭圆曲线推导后，后缀恰好命中规则。

## 原理

```
私钥 → secp256k1 公钥 → Keccak-256 → 0x41 + 后20字节 → Base58Check → T 开头地址
循环换私钥，直到地址尾部满足规则
```

默认规则：尾部连续 N 位均属于 `{6, 8, 9, A}`。  
命中概率约 `(4/58)^N`；每多一位大约难 58 倍。

## 构建

```bash
cargo build --release
```

## 用法

```bash
# 默认：7 连吉利后缀，找 1 个后退出
./target/release/jipinhao

# 8 连
./target/release/jipinhao -n 8

# 豹子号（尾部全相同，难度高很多）
./target/release/jipinhao -n 7 --same

# 指定线程与输出文件
./target/release/jipinhao -t 16 -o found.txt -m 5

# 校验私钥
./target/release/jipinhao --verify <64位十六进制私钥>
```

## 参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `-n, --length` | 连续位数 | 7 |
| `-c, --charset` | 吉利字符集 | 689A |
| `--same` | 要求后缀全相同（豹子号） | 关闭 |
| `-t, --threads` | 工作线程数 | CPU 核数 |
| `-o, --output` | 结果文件 | found.txt |
| `-m, --max-find` | 找到 N 个后退出（0=一直跑） | 1 |
| `--verify` | 仅做私钥→地址校验 | - |

## 安全提醒

命中结果含**私钥**，等同资产本身。勿提交到 Git、勿发到不可信渠道。仓库已将 `found.txt`、本地笔记与密钥文件加入 `.gitignore`。

## License

MIT

