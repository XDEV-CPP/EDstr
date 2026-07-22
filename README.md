# EDstr
一个纯C++头文件库，覆盖80+种加密/解密/哈希算法，专为CTF竞赛和密码学学习设计。

<div align="center">

![C++](https://img.shields.io/badge/C++-17-blue.svg?style=flat-square&logo=c%2B%2B)
![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg?style=flat-square)
![Lines](https://img.shields.io/badge/Code-16000%2B-orange.svg?style=flat-square)
![Algorithms](https://img.shields.io/badge/Algorithms-80%2B-red.svg?style=flat-square)

</div>

## ✨ 简介

**EDstr.hpp** 是一个纯头文件的 C++ 密码学工具箱，覆盖了从**古典密码**到**现代密码**、从**国际标准**到**各国国家标准**的广泛算法。无论是 CTF 竞赛中的 Crypto 题，还是密码学课程的学习，这个库都能为你提供强大的支持。

**所有代码均在一个头文件中，零依赖，包含即用！**

## 📦 已实现算法

### 🇨🇳 中国标准
- **SM3** / **SM4**

### 🇺🇸 美国标准
- **AES** (128/192/256) / **DES** / **3DES (TDEA)**
- **SHA-1** / **SHA-224** / **SHA-256** / **SHA-384** / **SHA-512**
- **SHA-3** (224/256/384/512) / **SHAKE128** / **SHAKE256**
- **CSHAKE** / **KMAC**

### 🇷🇺 俄罗斯标准 (GOST)
- **GOST 28147-89 (Magma)** / **Kuznyechik**
- **GOST R 34.10-94/2001/2012** (数字签名)
- **GOST R 34.11-94/2012 (Streebog)** (哈希)
- **GOST R 34.13-2015** (工作模式)
- **GOST R 34.17-2019** (GCM 模式)

### 🇯🇵 日本标准
- **Camellia** / **MISTY1** / **MISTY2** / **KASUMI**

### 🇰🇷 韩国标准
- **ARIA** / **SEED**

### 🇪🇺 欧洲/其他
- **IDEA** / **IDEA NXT**
- **Serpent** / **Twofish**
- **Blowfish** / **CAST-128** / **CAST-256**
- **RC2** / **RC4** / **RC5** / **RC6**
- **SAFER** (SK/K/PLUS/PP 全系列)
- **Skipjack**

### 🔐 非对称加密
- **RSA** (完整实现，含 Miller-Rabin 素数检测、密钥生成、加解密)

### 🌊 流加密
- **ChaCha20** / **Salsa20**

### 🧬 哈希函数
- **MD2** / **MD4** / **MD5**
- **SHA-0** / **SHA-1** / **SHA-2** / **SHA-3**
- **BLAKE2b** / **BLAKE2s** / **BLAKE3**
- **Whirlpool** / **Tiger** / **Tiger2**
- **RIPEMD-128** / **160** / **256** / **320**
- **HAVAL** (3/4/5 轮) / **MD6** / **Keccak**

### 🔑 密钥派生与消息认证
- **HMAC** (SHA-1/224/256/384/512/SHA-3)
- **PBKDF2** / **HKDF**
- **CMAC** / **KMAC**

### 📜 古典密码
- **凯撒 (Caesar)** / **维吉尼亚 (Vigenere)**
- **仿射 (Affine)** / **替换 (Substitution)**
- **栅栏 (Rail Fence)** / **列置换 (Columnar Transposition)**
- **Playfair** / **希尔 (Hill Cipher, 5×5)**

### 🔧 编码与校验
- **Base64** / **Base58** / **Base32**
- **CRC32** / **CRC64** / **Adler-32**
- **Hex** / **URL 编码**

## 📂 使用方法

```cpp
#include "EDstr.hpp"

// 哈希
std::string hash = sha256("hello world");

// AES 加密
std::vector<unsigned char> key(16, 0);
auto cipher = aes_encrypt(plaintext, key);

// RSA 密钥生成
unsigned long long e, n, d;
rsa_generate_keys(e, n, d, 128);

// ChaCha20 流加密
std::vector<unsigned char> nonce(12, 0);
auto cipher = chacha20_encrypt(plaintext, key, nonce);
```

## ⚠️ 免责声明

**请自行承担使用风险**

本软件按“现状”提供，不附带任何形式的明示或暗示保证，包括但不限于适销性、特定用途适用性和非侵权性的保证。在任何情况下，作者或版权持有人均不对任何索赔、损害或其他责任负责，无论是基于合同、侵权还是其他原因，因使用本头文件或与本头文件相关的使用或其他交易而产生。

**加密合规声明：** 本头文件包含加密功能。出口管制和当地法律因司法管辖区而异。用户有责任遵守所有适用的法律法规，包括但不限于各自国家的进出口法规（例如美国出口管理条例（EAR）、欧盟两用法规以及中华人民共和国密码法）。

**非专业建议：** 此处提供的信息不构成法律、安全或专业建议。请针对您的具体使用场景咨询合格的专业人士。

## 联系方式

邮箱：**3751385729@qq.com**

## 防伪标志

