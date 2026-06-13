# 网络安全传输实验系统

基于自实现加密算法的网络安全传输演示系统，在两台主机之间实现安全加密通信，包含完整的密钥协商、数据加密、消息认证和数字签名流程。

---

## 一、系统概述

本系统实现了两台主机之间的安全通信，综合运用以下密码学技术保障数据安全：

| 安全属性 | 实现方式 | 算法 |
|---------|---------|------|
| 机密性 | 对称加密 | AES-128-CBC（PKCS7填充） |
| 完整性 | 消息认证码 | HMAC-SHA256（RFC 2104） |
| 真实性 | 数字签名 | RSA-SHA256 签名验证 |
| 不可否认性 | 私钥签名 | RSA 私钥签名 + 公钥验证 |
| 密钥安全 | 密钥协商 | Diffie-Hellman（RFC 3526 2048-bit MODP） |

所有加密算法均为**从零自实现**，未使用任何第三方加密库（如 OpenSSL、PyCryptodome 等）。

---

## 二、采集数据

### 1、采集工具

本系统使用 **Scapy** 库进行网络数据包采集。Scapy 是一个强大的 Python 网络数据包操作库，能够直接与网卡交互，实现数据包的捕获、解析和构造。

**采集原理：**

Scapy 通过将网卡设置为**混杂模式（Promiscuous Mode）**，直接从数据链路层读取原始数据帧。在混杂模式下，网卡不仅接收发往本机 MAC 地址的数据帧，还会接收局域网内所有经过的数据帧。Scapy 使用 **BPF（Berkeley Packet Filter）** 过滤器在内核层面进行数据包筛选，只将符合条件的数据包传递给用户空间，从而减少无关流量，提高采集效率。

**采集过程：**

```
1. 初始化 Scapy 抓包引擎
   └─ 加载 scapy.all 模块，获取网卡列表

2. 选择网络接口
   └─ 自动选择有非 loopback IP 的网卡（优先使用 scapy 默认接口）
   └─ 也可手动指定网卡接口

3. 设置 BPF 过滤器
   └─ BPF 过滤器在内核层面工作，不符合规则的数据包直接丢弃
   └─ 常用过滤器：
      - "ip"             → 捕获所有 IP 数据包
      - "tcp"            → 仅捕获 TCP 数据包
      - "host 10.0.0.1"  → 仅捕获与指定 IP 通信的数据包
      - "tcp port 9999"  → 仅捕获指定端口的 TCP 数据包

4. 调用 sniff() 函数开始抓包
   └─ 参数：count（抓包数量）、timeout（超时时间）、filter（BPF 过滤规则）
   └─ 每收到一个数据包，调用回调函数 process_packet() 进行实时解析

5. 逐层解析数据包
   └─ 以太网层（Ether）：解析源 MAC、目标 MAC、以太网类型
   └─ 网络层（IP）：解析源 IP、目标 IP、TTL、IP 标志位、分片偏移
   └─ 传输层（TCP/UDP/ICMP）：解析端口号、TCP 标志位、序列号、确认号、窗口大小
   └─ 载荷层（Raw）：提取应用层数据的十六进制和 UTF-8 表示

6. 保存采集结果
   └─ 将解析后的数据包列表序列化为 JSON 格式
   └─ 写入固定文件 capture_latest.json（每次覆盖写入）
```

**采集代码（capture.py 核心逻辑）：**

```python
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, Ether

def capture_packets_scapy(count=10, timeout=15, filter_rule="ip"):
    """使用 scapy 抓取网络数据包"""

    packets_info = []  # 存储解析后的数据包信息
    capture_log = []   # 记录抓包过程日志

    # 自动选择网卡接口
    interface = _auto_select_interface()

    def process_packet(pkt):
        """每收到一个数据包的回调函数"""
        info = {"id": len(packets_info) + 1, "timestamp": ...}

        # 逐层解析
        if Ether in pkt:          # 以太网层
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst

        if IP in pkt:             # IP 层
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
            info["ttl"] = pkt[IP].ttl

            if TCP in pkt:        # TCP 层
                info["protocol"] = "TCP"
                info["src_port"] = pkt[TCP].sport
                info["dst_port"] = pkt[TCP].dport
                info["tcp_flags"] = _parse_tcp_flags(pkt[TCP].flags)
                info["seq_num"] = pkt[TCP].seq

            if Raw in pkt:        # 载荷
                raw_data = bytes(pkt[Raw])
                info["payload_hex"] = raw_data.hex()[:500]

        packets_info.append(info)

    # 执行抓包
    sniff(prn=process_packet, count=count, timeout=timeout,
          filter=filter_rule, iface=interface, store=False)

    return packets_info, capture_log
```

### 2、实验步骤

**完整的数据加密、认证、传输过程：**

```
发送端                                        接收端
  |                                             |
  |──── ① TCP 三次握手 ────────────────────────>|
  |      SYN                                    |
  |<─── SYN+ACK ────────────────────────────────|
  |──── ACK ──────────────────────────────────>|
  |                                             |
  |──── ② 交换 RSA 公钥 ──────────────────────>|
  |<─── RSA 公钥 ──────────────────────────────|
  |                                             |
  |──── ③ 交换 DH 公钥（带 RSA 签名）─────────>|
  |<─── DH 公钥 + RSA 签名 ────────────────────|
  |                                             |
  |      ④ 双方验证签名，计算共享会话密钥        |
  |      DH: 共享秘密 = g^(ab) mod p            |
  |      派生: AES 密钥 = SHA256(秘密)[:16]      |
  |      派生: HMAC 密钥 = SHA256(秘密)[16:32]   |
  |                                             |
  |──── ⑤ 加密传输 ──────────────────────────>|
  |      1. AES-128-CBC 加密明文 → 密文          |
  |      2. HMAC-SHA256(密文) → 认证码           |
  |      3. RSA 签名(密文) → 数字签名            |
  |      4. 打包: 密文+HMAC+IV+签名              |
  |                                             |
  |      接收端处理:                              |
  |      1. HMAC 验证 → 确认数据完整             |
  |      2. RSA 签名验证 → 确认发送方身份         |
  |      3. AES-128-CBC 解密 → 还原明文           |
```

**详细步骤说明：**

**步骤1：TCP 三次握手**
- 发送端向接收端的 9999 端口发起 TCP 连接
- SYN → SYN+ACK → ACK，建立可靠传输通道

**步骤2：交换 RSA 公钥**
- 双方互相发送自己的 RSA 公钥 (e, n)
- 后续用于验证对方的数字签名

**步骤3：交换 DH 公钥（带 RSA 签名）**
- 发送端：生成 DH 公钥 A = g^a mod p，用 RSA 私钥对 A 签名，发送 (A, signature)
- 接收端：生成 DH 公钥 B = g^b mod p，用 RSA 私钥对 B 签名，发送 (B, signature)

**步骤4：验证签名 + 计算会话密钥**
- 双方用对方 RSA 公钥验证签名，确认 DH 公钥未被篡改
- 双方独立计算共享秘密：s = B^a mod p = A^b mod p = g^(ab) mod p
- 从共享秘密派生密钥：SHA256(s) 的前16字节 = AES 密钥，后16字节 = HMAC 密钥

**步骤5：加密传输数据**
- 发送端：AES-128-CBC 加密 → HMAC-SHA256 认证 → RSA 签名 → 打包发送
- 接收端：HMAC 验证 → RSA 签名验证 → AES-128-CBC 解密 → 还原明文

### 3、主要代码及注释

**密钥协商核心代码（app.py）：**

```python
# 发送端发起密钥协商
@app.route('/api/connect', methods=['POST'])
def api_connect():
    # 步骤1: TCP 连接到接收端
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 步骤2: 发送 RSA 公钥
    send_msg(sock, {'type': 'rsa_pub', 'e': _rsa_pub[0], 'n': _rsa_pub[1]})

    # 步骤3: 接收对方 RSA 公钥
    resp = recv_msg(sock)
    peer_rsa_pub = (resp['e'], resp['n'])

    # 步骤4: 发送 DH 公钥 + RSA 签名
    dh_pub = _dh_peer.get_public_key()
    signature = rsa_sign(str(dh_pub).encode(), _rsa_priv)
    send_msg(sock, {'type': 'dh_pub', 'public_key': hex(dh_pub), 'signature': signature.hex()})

    # 步骤5: 接收对方 DH 公钥 + 验证签名
    resp = recv_msg(sock)
    peer_dh_pub = int(resp['public_key'], 16)
    peer_sig = bytes.fromhex(resp['signature'])
    if not rsa_verify(str(peer_dh_pub).encode(), peer_sig, peer_rsa_pub):
        raise ValueError("签名验证失败！")

    # 步骤6: 计算共享会话密钥
    _dh_peer.compute_shared_secret(peer_dh_pub)
    session_key = _dh_peer.get_session_key()   # AES-128 密钥（16字节）
    hmac_key = _dh_peer.get_hmac_key()         # HMAC 密钥（16字节）
```

**数据加密发送代码（app.py）：**

```python
@app.route('/api/send', methods=['POST'])
def api_send():
    plaintext = data.encode('utf-8')

    # 第1步: AES-128-CBC 加密
    ciphertext, iv = aes_encrypt(plaintext, session_key, mode='cbc')

    # 第2步: HMAC-SHA256 认证（对密文计算，确保密文完整性）
    hmac_value = hmac_sha256(hmac_key, ciphertext)

    # 第3步: RSA 数字签名（对密文签名，确保不可否认性）
    signature = rsa_sign(ciphertext, _rsa_priv)

    # 第4步: 打包传输（自定义协议格式，解决 TCP 粘包）
    packet = pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key,
                         hmac_value, iv=iv)

    # 第5步: 通过 TCP 发送
    send_data(host, port, packet)
```

**数据接收解密代码（app.py）：**

```python
def handle_received_data(encrypted_packet):
    # 解包
    ciphertext, enc_aes_key, enc_hmac_key, iv, recv_hmac = unpack_packet(encrypted_packet)

    # 第1步: HMAC-SHA256 完整性验证
    computed_hmac = hmac_sha256(hmac_key, ciphertext)
    if computed_hmac != recv_hmac:
        raise ValueError("HMAC 验证失败！数据可能被篡改")

    # 第2步: RSA 签名验证
    if not rsa_verify(ciphertext, signature, peer_rsa_pub):
        raise ValueError("签名验证失败！发送方身份不可信")

    # 第3步: AES-128-CBC 解密
    plaintext = aes_decrypt(ciphertext, session_key, mode='cbc', iv=iv)
```

---

## 三、加密解密算法

### 1、基本原理

#### AES-128-CBC 对称加密

AES（Advanced Encryption Standard）是一种分组密码，将明文分成固定长度（16字节）的块，逐块加密。

- **密钥长度**：128位（16字节）
- **分组大小**：128位（16字节）
- **加密轮数**：10轮
- **CBC模式**：每个明文块在加密前先与前一个密文块异或（C[i] = E(P[i] ⊕ C[i-1])），第一个块与随机IV异或，确保相同明文加密后产生不同密文
- **PKCS7填充**：将明文填充到16字节的整数倍

**AES-128 单块加密流程：**

```
明文块(16字节)
    ↓
AddRoundKey(轮密钥0)      ← 初始轮密钥加
    ↓
┌─────────────────────┐
│ SubBytes            │  ← S-Box 字节替换（非线性变换，提供混淆性）
│ ShiftRows           │  ← 行循环左移（提供扩散性）
│ MixColumns          │  ← GF(2^8) 列混合（提供扩散性）
│ AddRoundKey(轮密钥r)│  ← 轮密钥加
└─────────────────────┘
    ↓ 重复 9 轮（第1~9轮）
    ↓
SubBytes                  ← 第10轮（无 MixColumns）
ShiftRows
AddRoundKey(轮密钥10)
    ↓
密文块(16字节)
```

**CBC 模式加密：**

```
明文P[0]    明文P[1]    明文P[2]
  ⊕IV        ⊕C[0]      ⊕C[1]
   ↓           ↓           ↓
 AES加密     AES加密     AES加密
   ↓           ↓           ↓
密文C[0]    密文C[1]    密文C[2]
```

#### RSA 公钥加密与数字签名

RSA 基于大整数分解难题：已知 n = p × q，很难从 n 反推 p 和 q。

**密钥生成：**

```
1. 选择两个大素数 p, q
2. 计算模数 n = p × q
3. 计算欧拉函数 φ(n) = (p-1)(q-1)
4. 选择公钥指数 e，满足 1 < e < φ(n) 且 gcd(e, φ(n)) = 1
5. 计算私钥指数 d = e⁻¹ mod φ(n)（即 d × e ≡ 1 (mod φ(n))）
6. 公钥 = (e, n)，私钥 = (d, n)
```

**加密/解密：**

```
加密: c = m^e mod n    （用公钥加密）
解密: m = c^d mod n    （用私钥解密）
```

**数字签名：**

```
签名: s = SHA256(m)^d mod n    （对消息哈希用私钥签名）
验证: SHA256(m) == s^e mod n   （用公钥恢复哈希并比对）
```

### 2、主要代码及注释

**AES-128 密钥扩展（aes.py）：**

```python
def key_expansion(key):
    """AES-128 密钥扩展: 16字节密钥 → 11组轮密钥"""
    w = []  # 扩展密钥字数组
    for i in range(4):  # 前4个字直接从原始密钥取
        w.append(list(key[i*4:(i+1)*4]))

    for i in range(4, 44):  # 扩展剩余40个字
        temp = w[i-1][:]
        if i % 4 == 0:  # 每4个字进行一次特殊处理
            temp = _sub_word(_rot_word(temp))  # 循环左移 + S-Box替换
            temp[0] ^= RCON[i // 4]  # 异或轮常数
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])

    # 组织为11组轮密钥
    round_keys = []
    for r in range(11):
        rk = [[0]*4 for _ in range(4)]
        for c in range(4):
            for row in range(4):
                rk[row][c] = w[r*4 + c][row]
        round_keys.append(rk)
    return round_keys
```

**AES-128 CBC 模式加密（aes.py）：**

```python
def aes_encrypt(plaintext, key, mode='ecb', iv=None):
    """AES-128 加密（支持 ECB 和 CBC 模式）"""
    round_keys = key_expansion(key)       # 扩展密钥
    padded = _pkcs7_pad(plaintext)        # PKCS7 填充

    if mode == 'cbc':
        iv = os.urandom(16) if iv is None else iv  # CBC 需要 IV

    ciphertext = b''
    prev = iv  # 前一个密文块（CBC 用）

    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        if mode == 'cbc' and prev is not None:
            block = bytes(a ^ b for a, b in zip(block, prev))  # 与前一块异或
        encrypted = _aes_encrypt_block(block, round_keys)       # AES 加密
        ciphertext += encrypted
        prev = encrypted  # 更新前一个密文块

    return ciphertext, iv
```

**RSA 密钥生成（rsa.py）：**

```python
def generate_keypair(bits=512):
    """生成 RSA 密钥对"""
    p = _generate_prime(bits // 2)         # 生成素数 p
    q = _generate_prime(bits // 2)         # 生成素数 q
    while p == q:                          # 确保 p ≠ q
        q = _generate_prime(bits // 2)
    n = p * q                              # 模数 n = p × q
    phi_n = (p - 1) * (q - 1)             # 欧拉函数 φ(n)
    e = 65537                              # 公钥指数（费马素数）
    if _gcd(e, phi_n) != 1:               # 确保 e 与 φ(n) 互素
        e = 3
        while _gcd(e, phi_n) != 1:
            e += 2
    d = mod_inverse(e, phi_n)             # 私钥 d = e⁻¹ mod φ(n)
    return (e, n), (d, n)                 # 返回公钥和私钥
```

**RSA 数字签名（rsa.py）：**

```python
def rsa_sign(message_bytes, private_key):
    """RSA 数字签名: s = SHA256(m)^d mod n"""
    d, n = private_key
    msg_hash = sha256(message_bytes)       # 计算消息的 SHA-256 哈希
    h = int.from_bytes(msg_hash, 'big')    # 哈希值转整数
    signature = pow(h, d, n)               # 签名: h^d mod n
    byte_len = (n.bit_length() + 7) // 8
    return signature.to_bytes(byte_len, 'big')

def rsa_verify(message_bytes, signature_bytes, public_key):
    """RSA 签名验证: SHA256(m) == s^e mod n"""
    e, n = public_key
    s = int.from_bytes(signature_bytes, 'big')
    recovered_hash = pow(s, e, n)          # 恢复哈希: s^e mod n
    actual_hash = int.from_bytes(sha256(message_bytes), 'big')
    return recovered_hash == actual_hash   # 比较哈希是否一致
```

### 3、执行界面

**AES-128-CBC 加密界面展示：**

在发送端 Web 界面点击「加密并发送」后，显示以下加密过程：

```
第1步：AES-128-CBC 加密
  AES 密钥: a3f2c8...（16字节，由 DH 协商派生）
  IV: 7b1e9d...（16字节随机生成）
  明文长度: 234 字节
  密文长度: 240 字节（PKCS7 填充后）
  状态: ✓ 通过

第2步：HMAC-SHA256 认证
  HMAC 密钥: d4e5f6...（16字节，由 DH 协商派生）
  HMAC 值: 8a3b2c...（32字节）
  状态: ✓ 通过

第3步：RSA 数字签名
  签名算法: SHA256withRSA
  签名值: 2f8a1b...（64字节，512位 RSA）
  状态: ✓ 通过
```

---

## 四、消息认证（签名）

### HMAC-SHA256 消息认证码

HMAC（Hash-based Message Authentication Code）用于验证消息的**完整性**和**真实性**。

**基本原理（RFC 2104）：**

```
HMAC(K, m) = SHA256((K ⊕ opad) || SHA256((K ⊕ ipad) || m))

其中:
  K  = 认证密钥（本系统由 DH 共享秘密派生，16字节）
  m  = 待认证的消息（本系统为 AES 加密后的密文）
  ipad = 0x36 重复 64 次（内部填充）
  opad = 0x5c 重复 64 次（外部填充）
  ||  = 字符串拼接
  ⊕   = 逐字节异或
```

**计算过程：**

```
1. 密钥处理:
   - 若密钥 > 64 字节: key = SHA256(key)（压缩为 32 字节）
   - 若密钥 < 64 字节: key = key + 0x00...（补零到 64 字节）

2. 生成 ipad 和 opad:
   - ipad = key 的每个字节 ⊕ 0x36
   - opad = key 的每个字节 ⊕ 0x5c

3. 计算内部哈希:
   - inner = SHA256(ipad || message)

4. 计算最终哈希:
   - result = SHA256(opad || inner)

5. 输出 32 字节（256位）的 HMAC 值
```

**主要代码（hmac_sha256.py）：**

```python
def hmac_sha256(key, message):
    """HMAC-SHA256 计算，遵循 RFC 2104"""
    block_size = 64  # SHA-256 块大小

    # 步骤1: 处理密钥长度
    if len(key) > block_size:
        key = sha256(key)                          # 过长则先哈希
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))  # 过短则补零

    # 步骤2: 生成 ipad 和 opad
    ipad = bytes(k ^ 0x36 for k in key)            # 内部填充
    opad = bytes(k ^ 0x5c for k in key)            # 外部填充

    # 步骤3: 计算内部哈希
    inner_hash = sha256(ipad + message)

    # 步骤4: 计算最终哈希
    result = sha256(opad + inner_hash)

    return result  # 32 字节 HMAC 值
```

### RSA 数字签名

RSA 数字签名用于验证消息的**真实性**和**不可否认性**。

**签名与验证过程：**

```
签名方（发送端）:
  1. 计算消息哈希: h = SHA256(密文)
  2. 用私钥签名: s = h^d mod n
  3. 发送: 密文 + 签名 s

验证方（接收端）:
  1. 用公钥恢复哈希: h' = s^e mod n
  2. 计算实际哈希: h = SHA256(密文)
  3. 比较: h' == h → 签名有效（确认发送方身份，不可否认）
```

**在本系统中的应用：**

- **DH 公钥交换时签名**：发送端用 RSA 私钥对自己的 DH 公钥签名，接收端用发送端的 RSA 公钥验证，确保 DH 公钥未被中间人篡改
- **数据传输时签名**：发送端用 RSA 私钥对密文签名，接收端验证签名后确认数据来源可信

---

## 五、网络传输

### 自定义协议格式

本系统使用自定义二进制协议格式，通过 TCP 可靠传输通道发送加密数据。为解决 TCP **粘包问题**（多个数据包可能被合并接收），协议采用"先发长度、再发数据"的方式：

```
数据包格式:
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ 4字节: 总长度 │ 密文+密钥+IV+HMAC 组合数据                    │
│ (大端序整数)  │                                              │
└──────────────┴──────────────┴──────────────┴──────────────┘

组合数据内部格式:
┌────────┬──────┬────────┬──────┬────────┬──────┬──────┬────┬──────────┐
│4B:密文长│密文  │4B:AES密│加密的│4B:HMAC │加密的│4B:IV │IV │32B:HMAC值│
│        │      │钥长度  │AES密钥│密钥长度 │HMAC密│长度  │    │          │
│        │      │        │      │        │钥    │      │    │          │
└────────┴──────┴────────┴──────┴────────┴──────┴──────┴────┴──────────┘
```

### TCP 粘包问题解决

TCP 是流式协议，不保证消息边界。发送方连续发送两个数据包，接收方可能一次 recv 就收到两个包的数据（粘包），或者一次 recv 只收到半个包（半包）。

**解决方案：**

```python
def recv_exact(sock, n, timeout=10):
    """精确接收 n 字节数据，解决半包问题"""
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:              # 循环直到收够 n 字节
        chunk = sock.recv(n - len(data))
        if not chunk:                 # 连接断开
            raise ConnectionError("连接已断开")
        data += chunk
    return data

# 接收流程:
# 1. 先接收 4 字节 → 解析为数据包总长度
total_len = struct.unpack('>I', recv_exact(sock, 4))[0]
# 2. 再接收 total_len 字节 → 得到完整数据包
packet_data = recv_exact(sock, total_len)
```

### 密钥协商网络流程

密钥协商阶段使用 JSON 格式通信（同样采用先发长度再发数据的方式）：

```python
def send_msg(sock, data):
    """发送 JSON 消息（4字节长度 + JSON数据）"""
    msg = json.dumps(data).encode()
    sock.sendall(struct.pack('>I', len(msg)))  # 先发4字节长度
    sock.sendall(msg)                          # 再发JSON数据

def recv_msg(sock):
    """接收 JSON 消息"""
    length = struct.unpack('>I', _recv_exact(sock, 4))[0]  # 读4字节长度
    data = _recv_exact(sock, length)                         # 读JSON数据
    return json.loads(data.decode())
```

**协商过程的消息序列：**

```
发送端 → 接收端: {'type': 'hello', 'mode': 'sender'}
接收端 → 发送端: {'type': 'hello_ack', 'mode': 'receiver'}

发送端 → 接收端: {'type': 'rsa_pub', 'e': 65537, 'n': ...}
接收端 → 发送端: {'type': 'rsa_pub', 'e': 65537, 'n': ...}

发送端 → 接收端: {'type': 'dh_pub', 'public_key': '0x...', 'signature': '...'}
接收端 → 发送端: {'type': 'dh_pub', 'public_key': '0x...', 'signature': '...'}

发送端 → 接收端: {'type': 'ready'}
接收端 → 发送端: {'type': 'ready'}
```

### 网络传输代码（network.py）

```python
def pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=None):
    """将加密后的各部分数据打包为传输数据包"""
    packet = b''
    # 密文: 4字节长度 + 密文数据
    packet += struct.pack('>I', len(ciphertext))
    packet += ciphertext
    # 加密后的AES密钥: 4字节长度 + 密钥数据
    packet += struct.pack('>I', len(encrypted_aes_key))
    packet += encrypted_aes_key
    # 加密后的HMAC密钥: 4字节长度 + 密钥数据
    packet += struct.pack('>I', len(encrypted_hmac_key))
    packet += encrypted_hmac_key
    # IV: 4字节长度 + IV数据（0表示无IV）
    if iv is not None:
        packet += struct.pack('>I', len(iv))
        packet += iv
    else:
        packet += struct.pack('>I', 0)
    # HMAC值: 固定32字节
    packet += hmac_value
    return packet

def send_data(host, port, packet, timeout=10):
    """通过 TCP 发送数据包（先发4字节总长度，解决粘包）"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(struct.pack('>I', len(packet)))  # 总长度
    sock.sendall(packet)                          # 数据包
    sock.close()
```

---

## 部署说明

### 两台局域网虚拟机部署

**网络拓扑：**

```
┌─────────────────────┐       局域网        ┌─────────────────────┐
│  发送端 VM (node8)   │                     │  接收端 VM (node7)   │
│  IP: 192.168.157.208 │◄──────────────────►│  IP: 192.168.157.207 │
│  Web: :5000         │    TCP :9999        │  Web: :5001         │
└─────────────────────┘                     └─────────────────────┘
```

**部署步骤：**

```bash
# 两台 VM 都拉取镜像
docker pull crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs:latest

# 接收端 VM 启动容器
docker run -d --name netsec-receiver --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=receiver -e FLASK_HOST=0.0.0.0 -e FLASK_PORT=5001 -e LISTEN_PORT=9999 \
  crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs:latest

# 发送端 VM 启动容器
docker run -d --name netsec-sender --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=sender -e FLASK_HOST=0.0.0.0 -e FLASK_PORT=5000 -e LISTEN_PORT=9999 \
  crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs:latest
```

**操作流程：**

1. 接收端打开 `http://<接收端IP>:5001` → 点击「我是接收端」
2. 发送端打开 `http://<发送端IP>:5000` → 点击「我是发送端」
3. 发送端输入接收端 IP 和端口 9999 → 点击「连接」
4. 观察 5 步密钥协商过程
5. 发送端抓包 → 加密发送
6. 接收端刷新 → 查看解密结果

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MODE` | `sender` | 运行模式（可在 Web 界面切换） |
| `FLASK_HOST` | `0.0.0.0` | Web 监听地址 |
| `FLASK_PORT` | `5000` | Web 端口（接收端用 5001） |
| `LISTEN_PORT` | `9999` | 协商服务器端口 |
| `RSA_BITS` | `512` | RSA 密钥位数 |

### 项目结构

```
├── sha256.py          # SHA-256 哈希算法（FIPS 180-4）
├── aes.py             # AES-128-CBC 对称加密（FIPS-197）
├── rsa.py             # RSA 公钥加密 + 数字签名
├── hmac_sha256.py     # HMAC-SHA256 消息认证码（RFC 2104）
├── dh.py              # Diffie-Hellman 密钥协商（RFC 3526）
├── capture.py         # 网络数据包采集（Scapy）
├── network.py         # Socket 网络传输（自定义协议）
├── app.py             # Flask Web 应用
├── templates/
│   └── index.html     # Web 前端界面
├── Dockerfile         # Docker 镜像构建
└── docker-compose.yml # Docker Compose 编排
```
