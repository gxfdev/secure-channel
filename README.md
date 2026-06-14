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

**网络获取数据的过程：**

```
┌──────────────────────────────────────────────────────────────┐
│                    网络数据包采集流程                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ① 初始化 Scapy 抓包引擎                                     │
│     └─ 加载 scapy.all 模块，获取系统网卡列表                   │
│                                                              │
│  ② 自动选择网络接口                                          │
│     └─ 优先使用 scapy 默认接口（conf.iface）                  │
│     └─ 若默认接口不可用，遍历所有接口找有非loopback IP的网卡    │
│     └─ 最后回退让 scapy 自行选择                              │
│                                                              │
│  ③ 设置 BPF 过滤器                                           │
│     └─ BPF 在内核层面工作，不符合规则的数据包直接丢弃           │
│     └─ 常用过滤器:                                            │
│        "ip"             → 捕获所有 IP 数据包                  │
│        "tcp"            → 仅捕获 TCP 数据包                   │
│        "host 10.0.0.1"  → 仅捕获与指定 IP 通信的数据包         │
│        "tcp port 9999"  → 仅捕获指定端口的 TCP 数据包          │
│                                                              │
│  ④ 调用 sniff() 函数开始抓包                                  │
│     └─ 参数: count(抓包数量), timeout(超时), filter(BPF规则)   │
│     └─ 每收到一个数据包，调用回调函数 process_packet() 实时解析 │
│                                                              │
│  ⑤ 逐层解析数据包（从底层到高层）                              │
│     └─ 以太网层(Ether): 源MAC、目标MAC、以太网类型             │
│     └─ 网络层(IP): 源IP、目标IP、TTL、IP标志位、分片偏移       │
│     └─ 传输层(TCP/UDP/ICMP): 端口号、TCP标志位、序列号、窗口   │
│     └─ 载荷层(Raw): 应用层数据的十六进制和UTF-8表示            │
│                                                              │
│  ⑥ 保存采集结果                                              │
│     └─ 将解析后的数据包列表序列化为 JSON 格式                  │
│     └─ 写入 capture_latest.json（每次覆盖写入）               │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Scapy 抓包原理：**

Scapy 通过将网卡设置为**混杂模式（Promiscuous Mode）**，直接从数据链路层读取原始数据帧。在混杂模式下，网卡不仅接收发往本机 MAC 地址的数据帧，还会接收局域网内所有经过的数据帧。Scapy 使用 **BPF（Berkeley Packet Filter）** 过滤器在内核层面进行数据包筛选，只将符合条件的数据包传递给用户空间，从而减少无关流量，提高采集效率。

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
- 三次握手确保双方都有发送和接收能力，防止已失效的连接请求到达服务器

**步骤2：交换 RSA 公钥**
- 双方互相发送自己的 RSA 公钥 (e, n)
- 后续用于验证对方的数字签名，确保 DH 公钥未被中间人替换

**步骤3：交换 DH 公钥（带 RSA 签名）**
- 发送端：生成 DH 公钥 A = g^a mod p，用 RSA 私钥对 A 签名，发送 (A, signature)
- 接收端：生成 DH 公钥 B = g^b mod p，用 RSA 私钥对 B 签名，发送 (B, signature)
- RSA 签名保证 DH 公钥的真实性，防止中间人攻击

**步骤4：验证签名 + 计算会话密钥**
- 双方用对方 RSA 公钥验证签名，确认 DH 公钥未被篡改
- 双方独立计算共享秘密：s = B^a mod p = A^b mod p = g^(ab) mod p
- 从共享秘密派生密钥：SHA256(s) 的前16字节 = AES 密钥，后16字节 = HMAC 密钥

**步骤5：加密传输数据**
- 发送端：AES-128-CBC 加密 → HMAC-SHA256 认证 → RSA 签名 → 打包发送
- 接收端：HMAC 验证 → RSA 签名验证 → AES-128-CBC 解密 → 还原明文

### 3、主要代码及注释

**抓包核心代码（capture.py）：**

```python
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, Ether

def capture_packets_scapy(count=10, timeout=15, interface=None, filter_rule="ip"):
    """使用 scapy 抓取网络数据包（详细版）"""
    packets_info = []  # 存储解析后的数据包信息
    capture_log = []   # 记录抓包过程日志

    # 自动选择网卡接口（优先选择非loopback的有IP网卡）
    interface = _auto_select_interface()

    def process_packet(pkt):
        """每收到一个数据包的回调函数，逐层解析"""
        info = {"id": len(packets_info) + 1, "timestamp": ...}

        # 以太网层：解析源MAC、目标MAC
        if Ether in pkt:
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst

        # IP 层：解析源IP、目标IP、TTL
        if IP in pkt:
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
            info["ttl"] = pkt[IP].ttl

            # TCP 层：解析端口号、标志位、序列号
            if TCP in pkt:
                info["protocol"] = "TCP"
                info["src_port"] = pkt[TCP].sport
                info["dst_port"] = pkt[TCP].dport
                info["tcp_flags"] = _parse_tcp_flags(pkt[TCP].flags)

            # 载荷层：提取应用层数据
            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                info["payload_hex"] = raw_data.hex()[:500]

        packets_info.append(info)

    # 执行抓包：count=数量, timeout=超时, filter=BPF过滤规则
    sniff(prn=process_packet, count=count, timeout=timeout,
          filter=filter_rule, iface=interface, store=False)

    return packets_info, capture_log
```

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

本系统涉及四种核心密码学算法：SHA-256 哈希、AES-128-CBC 对称加密、RSA 公钥加密、Diffie-Hellman 密钥协商。它们协同工作，共同保障数据的机密性、完整性和真实性。

#### SHA-256 哈希算法

SHA-256 是本系统的基础算法，AES 密钥扩展、HMAC 计算、RSA 签名均依赖它。

**基本原理（FIPS 180-4）：**

SHA-256 将任意长度的消息压缩为固定 256 位（32 字节）的哈希值。核心是一个**压缩函数**，对 512 位的消息块进行 64 轮运算。

```
消息 → 填充(追加1+0+64位长度) → 分成512位的块 → 逐块压缩 → 256位哈希值

压缩函数每轮运算:
  a,b,c,d,e,f,g,h = 8个32位工作变量
  W[t] = 消息扩展后的字

  T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
  T2 = Σ0(a) + Maj(a,b,c)
  h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2

其中:
  Ch(x,y,z)  = (x & y) ^ (~x & z)       选择函数
  Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)  多数函数
  Σ0(x) = ROTR2(x) ^ ROTR13(x) ^ ROTR22(x)  大写Sigma0
  Σ1(x) = ROTR6(x) ^ ROTR11(x) ^ ROTR25(x)  大写Sigma1
```

**安全特性：**
- **单向性**：从哈希值无法反推原始消息
- **抗碰撞性**：找不到两个不同消息产生相同哈希（2^128 工作量）
- **雪崩效应**：输入微小改变导致输出剧烈变化

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

**密钥扩展：** 16字节原始密钥通过密钥扩展算法生成 11 组轮密钥（共 176 字节），每轮使用不同的轮密钥。扩展过程使用 S-Box 替换、字循环左移（RotWord）和轮常数异或（Rcon）。

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

**素性检测：** 使用 Miller-Rabin 算法检测大整数是否为素数，进行 20 轮检测，错误概率 < 2^(-40)。

#### Diffie-Hellman 密钥协商

DH 算法允许双方在不安全的信道上协商出共享密钥，即使窃听者截获所有通信也无法推算出密钥。

**基本原理：**

```
公开参数: p（RFC 3526 2048位素数）, g = 2（生成元）

发送端:  随机生成私钥 a，计算公钥 A = g^a mod p
接收端:  随机生成私钥 b，计算公钥 B = g^b mod p

双方交换公钥后:
  发送端计算: s = B^a mod p = (g^b)^a mod p = g^(ab) mod p
  接收端计算: s = A^b mod p = (g^a)^b mod p = g^(ab) mod p

→ 双方得到相同的共享秘密 s，但窃听者无法从 A, B 推算出 s（离散对数难题）

密钥派生:
  hash = SHA256(s)
  AES 密钥 = hash[:16]    （前16字节，用于AES-128-CBC加密）
  HMAC 密钥 = hash[16:32]  （后16字节，用于HMAC-SHA256认证）
```

### 2、主要代码及注释

#### SHA-256 实现（sha256.py）

```python
# SHA-256 初始哈希值（前8个素数的平方根小数部分前32位）
INIT_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# SHA-256 轮常数（前64个素数的立方根小数部分前32位）
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, ...]  # 共64个

MASK32 = 0xFFFFFFFF  # 32位掩码，确保运算在32位范围内

def _rotr(x, n):
    """32位循环右移（右侧移出的位从左侧补回）"""
    return ((x >> n) | (x << (32 - n))) & MASK32

def _ch(x, y, z):
    """选择函数Ch: x的每位为1则选y对应位，为0则选z对应位"""
    return (x & y) ^ ((~x) & z)

def _maj(x, y, z):
    """多数函数Maj: 三个输入的对应位中，取多数值"""
    return (x & y) ^ (x & z) ^ (y & z)

def _sigma0(x):
    """大写Sigma0: ROTR(2) XOR ROTR(13) XOR ROTR(22)，用于压缩函数"""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _sigma1(x):
    """大写Sigma1: ROTR(6) XOR ROTR(11) XOR ROTR(25)，用于压缩函数"""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _gamma0(x):
    """小写sigma0: ROTR(7) XOR ROTR(18) XOR SHR(3)，用于消息调度"""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

def _gamma1(x):
    """小写sigma1: ROTR(17) XOR ROTR(19) XOR SHR(10)，用于消息调度"""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)

def _pad_message(message):
    """消息填充: 追加0x80 + 补0 + 8字节原始消息长度（大端序）"""
    msg_bits = len(message) * 8
    message += b'\x80'  # 追加1位'1'
    while len(message) % 64 != 56:  # 补0直到长度≡56(mod 64)
        message += b'\x00'
    message += msg_bits.to_bytes(8, 'big')  # 追加64位消息长度
    return message

def sha256(message):
    """SHA-256 主函数: 填充 → 分块 → 消息调度(扩展64字) → 压缩(64轮) → 输出32字节"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    message = _pad_message(message)
    h0, h1, h2, h3, h4, h5, h6, h7 = INIT_HASH

    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]
        # 消息调度: 16字 → 64字
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(block[i*4:(i+1)*4], 'big')
        for i in range(16, 64):
            w[i] = (_gamma1(w[i-2]) + w[i-7] + _gamma0(w[i-15]) + w[i-16]) & MASK32

        # 压缩函数: 64轮运算
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):
            t1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + w[i]) & MASK32
            t2 = (_sigma0(a) + _maj(a, b, c)) & MASK32
            h, g, f = g, f, e
            e = (d + t1) & MASK32
            d, c, b = c, b, a
            a = (t1 + t2) & MASK32

        h0 = (h0 + a) & MASK32; h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32; h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32; h5 = (h5 + f) & MASK32
        h6 = (h6 + g) & MASK32; h7 = (h7 + h) & MASK32

    return b''.join(x.to_bytes(4, 'big') for x in [h0, h1, h2, h3, h4, h5, h6, h7])
```

#### AES-128 实现（aes.py）

```python
# AES S-Box（FIPS-197标准替换盒，提供非线性变换/混淆性）
S_BOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, ...]  # 共256个值

# 逆S-Box（解密用，是S-Box的逆映射）
INV_S_BOX = [0]*256
for _i in range(256):
    INV_S_BOX[S_BOX[_i]] = _i  # S_BOX[x]=y → INV_S_BOX[y]=x

# 轮常数（用于密钥扩展，每轮异或不同的常数）
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _gmul(a, b):
    """GF(2^8) 有限域乘法（MixColumns步骤使用）
    特殊之处: 多项式乘法后要对不可约多项式 x^8+x^4+x^3+x+1 取模
    """
    p = 0
    for _ in range(8):
        if b & 1: p ^= a       # GF(2^8)中加法=异或
        hi = a & 0x80           # 检查最高位
        a = (a << 1) & 0xff    # 左移1位
        if hi: a ^= 0x1b       # 若溢出则异或不可约多项式
        b >>= 1
    return p

def _bytes_to_state(data):
    """16字节 → 4x4状态矩阵（AES使用列优先存储）"""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]  # 列优先填充
    return state

def _sub_bytes(state):
    """SubBytes: 对状态矩阵的每个字节进行S-Box替换（非线性变换，提供混淆性）"""
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(state):
    """ShiftRows: 对状态矩阵的行进行循环左移（提供扩散性）
    第0行不移，第1行左移1，第2行左移2，第3行左移3
    """
    return [
        state[0][:],                        # 第0行：不移动
        state[1][1:] + state[1][:1],        # 第1行：左移1字节
        state[2][2:] + state[2][:2],        # 第2行：左移2字节
        state[3][3:] + state[3][:3],        # 第3行：左移3字节
    ]

def _mix_columns(state):
    """MixColumns: 对状态矩阵的每列进行GF(2^8)矩阵乘法（提供扩散性）
    固定矩阵: [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
    """
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        result[0][c] = _gmul(2, s0) ^ _gmul(3, s1) ^ s2 ^ s3
        result[1][c] = s0 ^ _gmul(2, s1) ^ _gmul(3, s2) ^ s3
        result[2][c] = s0 ^ s1 ^ _gmul(2, s2) ^ _gmul(3, s3)
        result[3][c] = _gmul(3, s0) ^ s1 ^ s2 ^ _gmul(2, s3)
    return result

def _add_round_key(state, round_key):
    """AddRoundKey: 状态矩阵与轮密钥逐字节异或（引入密钥信息）"""
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

def key_expansion(key):
    """AES-128 密钥扩展: 16字节密钥 → 11组轮密钥"""
    w = []
    for i in range(4):  # 前4个字直接从原始密钥取
        w.append(list(key[i*4:(i+1)*4]))
    for i in range(4, 44):  # 扩展剩余40个字
        temp = w[i-1][:]
        if i % 4 == 0:  # 每4个字进行一次特殊处理
            temp = _sub_word(_rot_word(temp))  # 循环左移 + S-Box替换
            temp[0] ^= RCON[i // 4]           # 异或轮常数
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    # 组织为11组轮密钥（4x4矩阵）
    round_keys = []
    for r in range(11):
        rk = [[0]*4 for _ in range(4)]
        for c in range(4):
            for row in range(4):
                rk[row][c] = w[r*4 + c][row]
        round_keys.append(rk)
    return round_keys

def _pkcs7_pad(data, block_size=16):
    """PKCS7填充: 在数据末尾填充N个值为N的字节，使总长度为block_size的整数倍"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _aes_encrypt_block(block, round_keys):
    """AES-128 单块(16字节)加密
    流程: AddRoundKey(0) → [SubBytes→ShiftRows→MixColumns→AddRoundKey]×9轮
          → SubBytes→ShiftRows→AddRoundKey(10)
    """
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])  # 初始轮密钥加
    for r in range(1, 10):  # 第1~9轮
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    # 第10轮（无MixColumns）
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)

def aes_encrypt(plaintext, key, mode='ecb', iv=None):
    """AES-128 加密（支持ECB和CBC模式）
    CBC模式: 每个明文块先与前一个密文块异或再加密，安全性高于ECB
    """
    if len(key) != 16:
        raise ValueError("AES-128 密钥长度必须为16字节")
    round_keys = key_expansion(key)
    padded = _pkcs7_pad(plaintext)
    if mode == 'cbc':
        iv = os.urandom(16) if iv is None else iv  # CBC模式需要随机IV
    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        if mode == 'cbc' and prev is not None:
            block = bytes(a ^ b for a, b in zip(block, prev))  # 明文⊕前一个密文块
        encrypted = _aes_encrypt_block(block, round_keys)
        ciphertext += encrypted
        prev = encrypted  # 更新前一个密文块
    return ciphertext, iv

def aes_decrypt(ciphertext, key, mode='ecb', iv=None):
    """AES-128 解密（CBC模式: 解密后与前一个密文块异或还原明文）"""
    if len(key) != 16:
        raise ValueError("AES-128 密钥长度必须为16字节")
    if len(ciphertext) % 16 != 0:
        raise ValueError("密文长度必须是16的整数倍")
    round_keys = key_expansion(key)
    plaintext = b''
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = _aes_decrypt_block(block, round_keys)
        if mode == 'cbc' and prev is not None:
            decrypted = bytes(a ^ b for a, b in zip(decrypted, prev))
        plaintext += decrypted
        prev = block  # 注意：这里用的是密文块，不是解密后的明文
    return _pkcs7_unpad(plaintext)
```

#### RSA 实现（rsa.py）

```python
def _gcd(a, b):
    """欧几里得算法求最大公约数（用于判断两个数是否互素）"""
    while b:
        a, b = b, a % b
    return a

def _extended_gcd(a, b):
    """扩展欧几里得算法（求ax+by=gcd(a,b)的整数解x,y）"""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(a, m):
    """求a关于模m的模逆元（即求x使得 a*x ≡ 1 (mod m)）"""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"模逆元不存在: gcd({a}, {m}) = {g}")
    return x % m

def _miller_rabin(n, k=20):
    """Miller-Rabin 素性检测（概率性检测，k=20时错误概率<2^-40）
    原理：如果n是素数，则对于某些a，a^(n-1) ≡ 1 (mod n)
    """
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    # 将n-1分解为 2^s * d（d是奇数）
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False  # n是合数
    return True  # n很可能是素数

def generate_keypair(bits=1024):
    """生成 RSA 密钥对: 公钥(e,n), 私钥(d,n)
    流程: 生成两个大素数p,q → 计算n=p*q → 计算φ(n)=(p-1)(q-1)
          → 选e → 算d=e^(-1) mod φ(n)
    """
    half_bits = bits // 2
    p = _generate_prime(half_bits)
    q = _generate_prime(half_bits)
    while p == q:
        q = _generate_prime(half_bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # 优先尝试费马素数作为公钥指数e
    fermat_primes = [65537, 257, 17, 5, 3]
    random.shuffle(fermat_primes)
    e = None
    for candidate in fermat_primes:
        if candidate < phi_n and _gcd(candidate, phi_n) == 1:
            e = candidate; break
    if e is None:
        e = random.randrange(65537, 1 << 20, 2)
        while _gcd(e, phi_n) != 1:
            e = random.randrange(3, min(phi_n, 1 << 20), 2)
    d = mod_inverse(e, phi_n)  # 私钥指数d = e^(-1) mod φ(n)
    return (e, n), (d, n)

def rsa_encrypt(message_int, public_key):
    """RSA 加密: c = m^e mod n"""
    e, n = public_key
    if message_int >= n: message_int = message_int % n
    return pow(message_int, e, n)

def rsa_decrypt(ciphertext_int, private_key):
    """RSA 解密: m = c^d mod n"""
    d, n = private_key
    return pow(ciphertext_int, d, n)

def rsa_encrypt_bytes(data, public_key):
    """RSA 加密字节序列，支持分段加密"""
    e, n = public_key
    m = int.from_bytes(data, 'big')
    if m < n:
        c = rsa_encrypt(m, public_key)
        byte_len = (n.bit_length() + 7) // 8
        return c.to_bytes(byte_len, 'big')
    else:
        # 分段加密：每段不超过n的位数
        n_byte_len = max(1, (n.bit_length() - 1) // 8)
        chunks = []
        for i in range(0, len(data), n_byte_len):
            chunk = data[i:i + n_byte_len]
            chunk_int = int.from_bytes(chunk, 'big')
            c = rsa_encrypt(chunk_int, public_key)
            byte_len = (n.bit_length() + 7) // 8
            chunks.append(c.to_bytes(byte_len, 'big'))
        return len(chunks).to_bytes(4, 'big') + b''.join(chunks)
```

#### Diffie-Hellman 实现（dh.py）

```python
# RFC 3526 2048-bit MODP Group（公开的大素数p和生成元g）
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    # ... 完整2048位素数 ...
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2  # 生成元

class DHPeer:
    """DH 密钥协商参与方"""
    def __init__(self, bits=512, prime=None, generator=None):
        self.p = prime or DH_PRIME  # 使用RFC 3526标准素数
        self.g = generator or DH_GENERATOR
        self.private_key = random.getrandbits(bits)  # 随机生成私钥
        self.public_key = pow(self.g, self.private_key, self.p)  # 公钥 = g^a mod p
        self.shared_secret = None
        self.session_key = None

    def compute_shared_secret(self, other_public_key):
        """计算共享密钥: (对方公钥)^本方私钥 mod p
        数学: (g^b)^a mod p = g^(ab) mod p，双方得到相同的共享秘密
        """
        if other_public_key <= 1 or other_public_key >= self.p:
            raise ValueError("对方公钥无效")
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        # 将共享秘密哈希后派生密钥
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, 'big')
        from sha256 import sha256
        key_hash = sha256(secret_bytes)  # SHA-256输出32字节
        self.session_key = key_hash[:16]   # 前16字节 → AES-128密钥
        self.hmac_key = key_hash[16:32]    # 后16字节 → HMAC密钥
        return self.shared_secret

    def get_session_key(self):
        """获取AES会话密钥（16字节）"""
        return self.session_key

    def get_hmac_key(self):
        """获取HMAC密钥（16字节）"""
        return self.hmac_key
```

### 3、执行界面

系统启动后，通过浏览器访问 `http://<主机IP>:5000` 即可看到操作界面。

**发送端界面功能：**
- 显示本机 IP、RSA 公钥信息
- 输入接收端 IP 和端口，点击"连接"发起密钥协商
- 连接成功后显示协商过程（TCP握手→RSA公钥交换→DH公钥交换→签名验证→密钥派生）
- 输入明文数据，点击"发送"进行加密传输
- 抓包功能：捕获并展示网络数据包详情

**接收端界面功能：**
- 自动启动协商服务器，等待发送端连接
- 显示接收到的加密数据及解密结果
- 显示 HMAC 验证、签名验证的通过状态
- 抓包功能：捕获并展示网络数据包详情

**界面关键展示：**

```
┌─────────────────────────────────────────────────┐
│  网络安全传输实验系统 v3.0                        │
│  模式: 发送端  │  本机IP: 10.0.0.7               │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─ 密钥信息 ──────────────────────────────┐    │
│  │ RSA 公钥: e=65537, n=1024位             │    │
│  │ DH 公钥: 0x3a7f...                      │    │
│  │ 会话密钥: a1b2c3d4e5f6... (AES-128)     │    │
│  │ HMAC密钥: 7890abcdef... (16字节)        │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
│  ┌─ 连接状态 ──────────────────────────────┐    │
│  │ 状态: 已连接  对端: 10.0.0.8:9999       │    │
│  │ 协商步骤:                                │    │
│  │  ✓ TCP三次握手完成                       │    │
│  │  ✓ RSA公钥交换完成                       │    │
│  │  ✓ DH公钥交换+签名验证完成               │    │
│  │  ✓ 会话密钥派生完成                      │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
│  ┌─ 数据传输 ──────────────────────────────┐    │
│  │ 明文: [Hello World________] [发送]       │    │
│  │ 密文(hex): 4a8b2c...                    │    │
│  │ HMAC: 7f3a9b...                         │    │
│  │ IV: e2d4c6...                           │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
│  ┌─ 抓包信息 ──────────────────────────────┐    │
│  │ #1 TCP [SYN] 10.0.0.7:54321→10.0.0.8:9999│   │
│  │ #2 TCP [SYN,ACK] 10.0.0.8:9999→...      │    │
│  │ #3 TCP [ACK] 10.0.0.7:54321→...         │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

---

## 四、消息认证（签名）

### 1、基本原理

消息认证解决两个核心安全问题：**完整性**（数据未被篡改）和**真实性**（数据确实来自声称的发送方）。本系统采用 HMAC-SHA256 消息认证码和 RSA 数字签名双重保障。

#### HMAC-SHA256 消息认证码

HMAC（Hash-based Message Authentication Code）是基于哈希函数的消息认证码，遵循 RFC 2104 标准。

**基本原理：**

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

其中:
  K'  = 密钥K（若K>64字节则K'=SHA256(K)，若K<64字节则补零到64字节）
  ipad = 0x36 重复64次（00110110）
  opad = 0x5c 重复64次（01011100）
  H   = SHA-256 哈希函数
  ||  = 字符串拼接
  ⊕   = 逐字节异或
```

**为什么用两次哈希（内外两层）？**

如果只用一次哈希 `H(K || m)`，攻击者可以在消息末尾追加数据并继续哈希计算（长度扩展攻击）。双层结构使得：
- 内层 `H(K' ⊕ ipad || m)` 产生固定长度的中间结果
- 外层 `H(K' ⊕ opad || inner_hash)` 将中间结果作为输入，攻击者无法从最终输出推算内层状态

**安全特性：**

| 安全属性 | 说明 |
|---------|------|
| 防篡改 | 任何对密文的修改都会导致 HMAC 值不同，接收方能立即检测到 |
| 防伪造 | 没有 HMAC 密钥的攻击者无法为任意消息生成有效的认证码 |
| 确定性 | 相同密钥和消息始终产生相同的 HMAC 值 |

**本系统中的使用方式：** 对 AES 加密后的**密文**计算 HMAC（即 Encrypt-then-MAC 模式），而非对明文计算。这是最安全的认证加密模式，因为：
1. 接收方可以先验证 HMAC 再解密，避免对篡改数据的解密操作
2. 即使密文被篡改，HMAC 验证会首先失败，攻击者无法获得任何明文信息

#### RSA 数字签名

数字签名提供**不可否认性**——发送方无法否认自己发送过该消息。

**基本原理：**

```
签名过程（发送方）:
  1. 计算消息哈希: h = SHA256(消息)
  2. 用私钥加密哈希: s = h^d mod n    （d是私钥，n是RSA模数）
  3. 签名值 s 随消息一起发送

验证过程（接收方）:
  1. 用公钥解密签名: h' = s^e mod n    （e是公钥，n是RSA模数）
  2. 计算消息哈希: h = SHA256(消息)
  3. 比较 h' == h mod n，相等则签名有效
```

**签名 vs HMAC 的区别：**

| 特性 | HMAC-SHA256 | RSA 数字签名 |
|------|-------------|-------------|
| 对称/非对称 | 对称（双方共享密钥） | 非对称（私钥签名，公钥验证） |
| 不可否认性 | 否（双方都能生成） | 是（只有私钥持有者能签名） |
| 计算速度 | 快（哈希运算） | 慢（大数模幂运算） |
| 用途 | 验证数据完整性 | 验证发送方身份 |

**本系统中的使用方式：**
- DH 公钥交换时：用 RSA 私钥对 DH 公钥签名，防止中间人替换 DH 公钥
- 数据传输时：用 RSA 私钥对密文签名，确保发送方身份不可否认

### 2、主要代码及注释

#### HMAC-SHA256 实现（hmac_sha256.py）

```python
from sha256 import sha256  # 导入自实现的SHA-256

def hmac_sha256(key, message):
    """
    HMAC-SHA256 计算（遵循 RFC 2104）
    HMAC(K, m) = SHA256((K⊕opad) || SHA256((K⊕ipad) || m))
    """
    block_size = 64  # SHA-256 的块大小为64字节（512位）

    # 步骤1: 处理密钥长度
    if len(key) > block_size:       # 密钥超过64字节
        key = sha256(key)           # 先哈希压缩为32字节
    if len(key) < block_size:       # 密钥不足64字节
        key = key + b'\x00' * (block_size - len(key))  # 右侧补零

    # 步骤2: 生成 ipad 和 opad
    # ipad: 密钥每个字节与0x36异或（0x36 = 00110110）
    # opad: 密钥每个字节与0x5c异或（0x5c = 01011100）
    ipad = bytes(k ^ 0x36 for k in key)  # 内部填充
    opad = bytes(k ^ 0x5c for k in key)  # 外部填充

    # 步骤3: 计算内层哈希 H((K'⊕ipad) || m)
    inner_hash = sha256(ipad + message)

    # 步骤4: 计算外层哈希 H((K'⊕opad) || inner_hash)
    result = sha256(opad + inner_hash)

    return result  # 返回32字节HMAC值
```

#### RSA 数字签名实现（rsa.py）

```python
from sha256 import sha256  # 使用自实现的SHA-256

def rsa_sign(message_bytes, private_key):
    """
    RSA 数字签名: s = SHA256(m)^d mod n
    先对消息计算SHA-256哈希，再用私钥对哈希值签名
    """
    d, n = private_key
    msg_hash = sha256(message_bytes)       # 计算消息的SHA-256哈希（32字节）
    h = int.from_bytes(msg_hash, 'big')    # 哈希值转整数
    if h >= n:
        h = h % n                          # 确保哈希值小于模数n
    signature = pow(h, d, n)               # 签名: h^d mod n（用私钥加密哈希值）
    byte_len = (n.bit_length() + 7) // 8
    return signature.to_bytes(byte_len, 'big')

def rsa_verify(message_bytes, signature_bytes, public_key):
    """
    RSA 签名验证:
    1. 从签名恢复哈希值: h' = s^e mod n
    2. 计算消息的实际哈希: h = SHA-256(message)
    3. 比较 h' == h mod n
    """
    e, n = public_key
    s = int.from_bytes(signature_bytes, 'big')
    recovered_hash = pow(s, e, n)          # 用公钥解密签名，恢复哈希值
    actual_hash = int.from_bytes(sha256(message_bytes), 'big')
    if actual_hash >= n:
        actual_hash = actual_hash % n
    return recovered_hash == actual_hash   # 比较恢复的哈希和实际哈希
```

#### 数据传输中的认证流程（app.py）

```python
# ===== 发送端：加密 + 认证 + 签名 =====
@app.route('/api/send', methods=['POST'])
def api_send():
    plaintext = data.encode('utf-8')

    # 第1步: AES-128-CBC 加密
    ciphertext, iv = aes_encrypt(plaintext, session_key, mode='cbc')

    # 第2步: HMAC-SHA256 认证（对密文计算，Encrypt-then-MAC）
    hmac_value = hmac_sha256(hmac_key, ciphertext)

    # 第3步: RSA 数字签名（对密文签名，确保不可否认性）
    signature = rsa_sign(ciphertext, _rsa_priv)

    # 第4步: 打包传输
    packet = pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key,
                         hmac_value, iv=iv)
    send_data(host, port, packet)

# ===== 接收端：验证 + 解密 =====
def handle_received_data(encrypted_packet):
    ciphertext, enc_aes_key, enc_hmac_key, iv, recv_hmac = unpack_packet(encrypted_packet)

    # 第1步: HMAC-SHA256 完整性验证（先验证再解密，最安全）
    computed_hmac = hmac_sha256(hmac_key, ciphertext)
    if computed_hmac != recv_hmac:
        raise ValueError("HMAC 验证失败！数据可能被篡改")

    # 第2步: RSA 签名验证（确认发送方身份）
    if not rsa_verify(ciphertext, signature, peer_rsa_pub):
        raise ValueError("签名验证失败！发送方身份不可信")

    # 第3步: 验证通过后才解密
    plaintext = aes_decrypt(ciphertext, session_key, mode='cbc', iv=iv)
```

### 3、执行界面

消息认证和签名过程在 Web 界面中实时展示：

```
┌─ 消息认证执行界面 ────────────────────────────────────────┐
│                                                           │
│  发送端认证过程:                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │ ① AES-CBC加密 → 密文(32字节)                       │   │
│  │ ② HMAC-SHA256(密文) → 认证码(32字节)               │   │
│  │    HMAC = SHA256((K⊕opad) || SHA256((K⊕ipad) || C))│   │
│  │ ③ RSA签名(密文) → 数字签名(128字节)                 │   │
│  │    签名 = SHA256(C)^d mod n                         │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  接收端验证过程:                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │ ① HMAC验证: ✓ 计算HMAC == 接收HMAC                 │   │
│  │    → 数据完整性确认，未被篡改                        │   │
│  │ ② RSA签名验证: ✓ 恢复哈希 == 实际哈希               │   │
│  │    → 发送方身份确认，不可否认                        │   │
│  │ ③ AES-CBC解密 → 明文还原                            │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  认证失败场景:                                             │
│  ┌────────────────────────────────────────────────────┐   │
│  │ ✗ HMAC验证失败 → 数据被篡改，拒绝解密               │   │
│  │ ✗ 签名验证失败 → 身份不可信，拒绝解密               │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## 五、网络传输

### 1、基本原理

本系统基于 TCP 协议进行网络传输，采用自定义二进制协议格式解决 TCP 粘包问题，并通过长度前缀法实现消息的可靠分帧。

#### TCP 协议与粘包问题

TCP 是面向字节流的协议，不保留消息边界。当发送方连续发送多条消息时，接收方可能：
- **粘包**：两条消息的数据被合并到一次 `recv()` 中
- **半包**：一条消息的数据被拆分到多次 `recv()` 中

```
发送方发送:  [消息A] [消息B]
                ↓
TCP字节流:  |.....消息A.....消息B.....|
                ↓
接收方可能:  recv() → 消息A的前半部分     （半包）
            recv() → 消息A的后半+消息B    （粘包）
```

#### 长度前缀法解决粘包

本系统采用**长度前缀法（Length-Prefix Framing）**：每条消息前加4字节长度字段，接收方先读4字节获取消息长度，再精确读取对应长度的数据。

```
发送格式:
┌──────────────┬──────────────────────────┐
│ 4字节: 长度N  │      N字节: 消息数据      │
│ (大端序整数)  │                          │
└──────────────┴──────────────────────────┘

接收流程:
  ① recv(4字节) → 解析长度N
  ② 循环recv直到收满N字节（解决半包）
  ③ 处理完整消息
  ④ 继续读下一条消息的4字节长度...
```

#### 自定义加密数据包格式

加密后的数据包包含多个字段，每个字段都用"4字节长度+数据"的方式编码：

```
┌─────────────────────────────────────────────────────────────────┐
│                    加密数据包格式                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [4字节: 密文长度] [密文数据]                                     │
│  [4字节: 加密AES密钥长度] [加密AES密钥数据]                       │
│  [4字节: 加密HMAC密钥长度] [加密HMAC密钥数据]                     │
│  [4字节: IV长度] [IV数据]  (CBC模式16字节, ECB模式为0)            │
│  [32字节: HMAC值]                                               │
│                                                                 │
│  总大小 = 4+密文长度 + 4+AES密钥长度 + 4+HMAC密钥长度             │
│         + 4+IV长度 + 32字节HMAC                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 密钥协商协议格式

密钥协商阶段使用 JSON 格式传输（通过同样的长度前缀法分帧）：

```
消息1: 发送方 → 接收方
  {"type": "rsa_pub", "e": 公钥指数, "n": 模数}

消息2: 接收方 → 发送方
  {"type": "rsa_pub", "e": 公钥指数, "n": 模数}

消息3: 发送方 → 接收方
  {"type": "dh_pub", "public_key": "0x...", "signature": "hex签名"}

消息4: 接收方 → 发送方
  {"type": "dh_pub", "public_key": "0x...", "signature": "hex签名"}
```

### 2、主要代码及注释

#### 数据包打包/解包（network.py）

```python
import struct  # 二进制数据打包/解包

def pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=None):
    """
    将加密后的各部分数据打包为传输数据包
    每个字段: [4字节长度(大端序)] + [数据]
    """
    packet = b''
    # 打包密文
    packet += struct.pack('>I', len(ciphertext))  # '>I' = 大端序4字节无符号整数
    packet += ciphertext
    # 打包加密后的AES密钥
    packet += struct.pack('>I', len(encrypted_aes_key))
    packet += encrypted_aes_key
    # 打包加密后的HMAC密钥
    packet += struct.pack('>I', len(encrypted_hmac_key))
    packet += encrypted_hmac_key
    # 打包IV（CBC模式有16字节IV，ECB模式为0）
    if iv is not None:
        packet += struct.pack('>I', len(iv))
        packet += iv
    else:
        packet += struct.pack('>I', 0)  # 长度写0表示无IV
    # HMAC值固定32字节，无需长度前缀
    packet += hmac_value
    return packet

def unpack_packet(data):
    """解析接收到的数据包，按编码顺序逐字段读取"""
    offset = 0
    # 读取密文
    ct_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    ciphertext = data[offset:offset + ct_len]
    offset += ct_len
    # 读取加密的AES密钥
    ek_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    encrypted_aes_key = data[offset:offset + ek_len]
    offset += ek_len
    # 读取加密的HMAC密钥
    eh_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    encrypted_hmac_key = data[offset:offset + eh_len]
    offset += eh_len
    # 读取IV
    iv_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    iv = data[offset:offset + iv_len] if iv_len > 0 else None
    offset += iv_len
    # 读取HMAC值（最后32字节）
    hmac_value = data[offset:offset + 32]
    return ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value
```

#### 精确接收与粘包处理（network.py）

```python
def recv_exact(sock, n, timeout=10):
    """
    精确接收 n 字节数据（解决TCP半包问题）
    TCP的recv()可能一次返回少于n字节的数据，需要循环接收
    """
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:           # 循环直到收够n字节
        chunk = sock.recv(n - len(data))  # 接收剩余需要的字节数
        if not chunk:               # recv返回空 = 连接断开
            raise ConnectionError("连接已断开")
        data += chunk               # 追加已接收数据
    return data

def send_data(host, port, packet, timeout=10):
    """
    发送数据包（长度前缀法解决粘包）
    先发4字节总长度，再发完整数据包
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(struct.pack('>I', len(packet)))  # 先发4字节长度
        sock.sendall(packet)                           # 再发数据
        return True
    except Exception as e:
        return False
    finally:
        sock.close()
```

#### 密钥协商消息收发（app.py）

```python
def _recv_exact(sock, n):
    """精确接收n字节"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接断开")
        data += chunk
    return data

def send_msg(sock, msg_dict):
    """发送JSON消息（长度前缀法解决粘包）"""
    data = json.dumps(msg_dict).encode('utf-8')
    sock.sendall(struct.pack('>I', len(data)) + data)

def recv_msg(sock):
    """接收JSON消息（先读4字节长度，再读对应长度的数据）"""
    length_data = _recv_exact(sock, 4)
    msg_len = struct.unpack('>I', length_data)[0]
    msg_data = _recv_exact(sock, msg_len)
    return json.loads(msg_data.decode('utf-8'))

# 发送端协商流程
def negotiate_as_sender(sock, rsa_pub, rsa_priv, dh_peer):
    # 步骤1: 发送RSA公钥
    send_msg(sock, {'type': 'rsa_pub', 'e': rsa_pub[0], 'n': rsa_pub[1]})
    # 步骤2: 接收对方RSA公钥
    resp = recv_msg(sock)
    peer_rsa_pub = (resp['e'], resp['n'])
    # 步骤3: 发送DH公钥+RSA签名
    dh_pub = dh_peer.get_public_key()
    signature = rsa_sign(str(dh_pub).encode(), rsa_priv)
    send_msg(sock, {'type': 'dh_pub', 'public_key': hex(dh_pub), 'signature': signature.hex()})
    # 步骤4: 接收对方DH公钥+验证签名
    resp = recv_msg(sock)
    peer_dh_pub = int(resp['public_key'], 16)
    peer_sig = bytes.fromhex(resp['signature'])
    if not rsa_verify(str(peer_dh_pub).encode(), peer_sig, peer_rsa_pub):
        raise ValueError("签名验证失败！")
    # 步骤5: 计算共享会话密钥
    dh_peer.compute_shared_secret(peer_dh_pub)
    return dh_peer.get_session_key(), dh_peer.get_hmac_key(), peer_rsa_pub
```

### 3、执行界面

网络传输过程在 Web 界面中实时展示，包括 TCP 连接建立、密钥协商、数据传输的完整过程：

```
┌─ 网络传输执行界面 ────────────────────────────────────────┐
│                                                           │
│  ① 连接协商阶段                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │ 第1步: TCP 三次握手 ✓                               │   │
│  │   SYN → SYN+ACK → ACK                              │   │
│  │   发送端 10.0.0.1:随机端口 → 接收端 10.0.0.2:9999   │   │
│  │                                                     │   │
│  │ 第2步: RSA 公钥交换 ✓                               │   │
│  │   发送方 → 接收方: RSA公钥 (e=65537, n=2048位)      │   │
│  │   接收方 → 发送方: RSA公钥 (e=257, n=2048位)        │   │
│  │                                                     │   │
│  │ 第3步: DH 公钥交换 + 签名验证 ✓                     │   │
│  │   发送方 → 接收方: DH公钥A + RSA签名                │   │
│  │   接收方 → 发送方: DH公钥B + RSA签名                │   │
│  │   双方验证签名通过 ✓                                 │   │
│  │                                                     │   │
│  │ 第4步: 会话密钥派生 ✓                               │   │
│  │   共享秘密 = g^(ab) mod p                           │   │
│  │   AES密钥 = SHA256(秘密)[:16]                       │   │
│  │   HMAC密钥 = SHA256(秘密)[16:32]                    │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ② 数据传输阶段                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │ 发送: "Hello, 安全传输!"                             │   │
│  │   → AES-CBC加密 → 密文(32字节)                      │   │
│  │   → HMAC-SHA256 → 认证码(32字节)                    │   │
│  │   → RSA签名 → 数字签名(128字节)                      │   │
│  │   → 打包: [4B长度+密文][4B长度+AES密钥]              │   │
│  │          [4B长度+HMAC密钥][4B长度+IV][32B HMAC]      │   │
│  │   → TCP发送 ✓                                       │   │
│  │                                                     │   │
│  │ 接收:                                               │   │
│  │   → 读取4字节长度 → 读取完整数据包 ✓                 │   │
│  │   → 解包各字段 ✓                                    │   │
│  │   → HMAC验证 ✓ 数据完整                             │   │
│  │   → 签名验证 ✓ 身份确认                             │   │
│  │   → AES-CBC解密 → "Hello, 安全传输!" ✓              │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ③ 抓包面板                                               │
│  ┌────────────────────────────────────────────────────┐   │
│  │ 包1: TCP [SYN] 10.0.0.1:54321 → 10.0.0.2:9999     │   │
│  │ 包2: TCP [SYN,ACK] 10.0.0.2:9999 → 10.0.0.1:54321 │   │
│  │ 包3: TCP [ACK] 10.0.0.1:54321 → 10.0.0.2:9999     │   │
│  │ 包4: TCP [PSH,ACK] 载荷: 7c3a...f9e2 (加密数据)    │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## 六、部署说明

### 1、项目结构

```
网安/
├── app.py              # Flask 主应用（路由、密钥协商、数据收发）
├── aes.py              # AES-128-CBC 对称加密自实现
├── rsa.py              # RSA 公钥加密与数字签名自实现
├── dh.py               # Diffie-Hellman 密钥协商自实现
├── sha256.py           # SHA-256 哈希算法自实现
├── hmac_sha256.py      # HMAC-SHA256 消息认证码自实现
├── network.py          # TCP 网络传输（自定义协议、粘包处理）
├── capture.py          # Scapy 网络数据包采集模块
├── templates/
│   └── index.html      # Web 前端界面
├── Dockerfile          # Docker 镜像构建文件
├── docker-compose.yml  # Docker Compose 编排文件
├── Jenkinsfile         # Jenkins CI/CD 流水线
├── requirements.txt    # Python 依赖
└── README.md           # 项目说明文档
```

### 2、Docker 部署

#### Dockerfile 说明

```dockerfile
FROM python:3.11-slim

# 设置时区为中国标准时间
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 安装系统依赖（scapy 需要 tcpdump 和 libpcap-dev）
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制所有源代码
COPY . .

# Web 端口（Flask）和数据传输端口
EXPOSE 5000
EXPOSE 9999

# 环境变量（可通过 docker run -e 覆盖）
ENV MODE=sender
ENV RECEIVER_HOST=127.0.0.1
ENV RECEIVER_PORT=9999
ENV LISTEN_PORT=9999
ENV RSA_BITS=1024
ENV DATA_DIR=/app/captured_data
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000

# 数据目录可作为卷挂载
VOLUME /app/captured_data

CMD ["python", "app.py"]
```

#### 单机 Docker 部署

```bash
# 构建镜像
docker build -t secure-transport .

# 启动接收端（监听 9999 端口等待连接）
docker run -d --name receiver \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /root/captured_data:/app/captured_data \
  -e MODE=receiver \
  -e FLASK_HOST=0.0.0.0 \
  -e LISTEN_PORT=9999 \
  secure-transport

# 启动发送端（连接到接收端 IP）
docker run -d --name sender \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /root/captured_data:/app/captured_data \
  -e MODE=sender \
  -e RECEIVER_HOST=10.0.0.2 \
  -e FLASK_HOST=0.0.0.0 \
  -e RECEIVER_PORT=9999 \
  secure-transport
```

**注意：** `--cap-add NET_ADMIN --cap-add NET_RAW` 是 Scapy 抓包所需的网络权限，`--network host` 使容器直接使用宿主机网络栈，避免 NAT 导致的连接问题。

#### 双节点 Docker 部署（node7 接收端 + node8 发送端）

本系统部署在两台 Linux 服务器上，node7 作为接收端，node8 作为发送端，通过内网进行加密通信。

**网络拓扑：**

```
┌─────────────────────────────────────────────────────────────────┐
│                        内网 192.168.157.0/24                     │
│                                                                  │
│  ┌─────────────────────────┐      ┌─────────────────────────┐   │
│  │     node7 (接收端)       │      │     node8 (发送端)       │   │
│  │  IP: 192.168.157.207    │◄─────│  IP: 192.168.157.208    │   │
│  │                         │ TCP  │                         │   │
│  │  ┌───────────────────┐  │:9999 │  ┌───────────────────┐  │   │
│  │  │ netsec-receiver   │◄│──────│──│ netsec-sender     │  │   │
│  │  │ MODE=receiver     │  │      │  │ MODE=sender       │  │   │
│  │  │ LISTEN_PORT=9999  │  │      │  │ RECEIVER_HOST=    │  │   │
│  │  │ FLASK_PORT=5000   │  │      │  │   192.168.157.207 │  │   │
│  │  └───────────────────┘  │      │  │ FLASK_PORT=5000   │  │   │
│  │         ▲               │      │  └───────────────────┘  │   │
│  │         │ :5000         │      │         ▲               │   │
│  │    浏览器访问            │      │         │ :5000         │   │
│  │  http://192.168.157.207│      │    浏览器访问            │   │
│  │         :5000           │      │  http://192.168.157.208│   │
│  └─────────────────────────┘      │         :5000           │   │
│                                    └─────────────────────────┘   │
│                                                                  │
│  通信流程:                                                       │
│  1. node8 发送端 → TCP连接 → node7:9999 (密钥协商)               │
│  2. node8 加密数据 → TCP传输 → node7:9999 (数据传输)             │
│  3. 浏览器 → HTTP → node7:5000 / node8:5000 (Web管理界面)       │
└─────────────────────────────────────────────────────────────────┘
```

**前置条件（两台节点均需执行）：**

```bash
# 1. 确保 Docker 已安装
docker --version
# 若未安装:
curl -fsSL https://get.docker.com | sh
systemctl enable docker && systemctl start docker

# 2. 确保 Docker Compose 已安装
docker compose version
# 若未安装:
apt-get update && apt-get install -y docker-compose-plugin

# 3. 创建数据存储目录
mkdir -p /root/captured_data

# 4. 确认网络互通
# 在 node7 上:
ping -c 3 192.168.157.208
# 在 node8 上:
ping -c 3 192.168.157.207

# 5. 确认端口未被占用
ss -tlnp | grep -E '5000|9999'
```

---

**node7 部署步骤（接收端 192.168.157.207）：**

```bash
# ===== 步骤1: 拉取镜像 =====
# 方式A: 从 GitHub Container Registry 拉取
echo '你的GHCR_TOKEN' | docker login ghcr.io -u gxfdev --password-stdin
docker pull ghcr.io/gxfdev/secure-channel:latest

# 方式B: 从阿里云 ACR 拉取
docker pull crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs:latest

# 方式C: 本地构建（需要先 git clone 项目）
git clone https://github.com/gxfdev/secure-channel.git
cd secure-channel
docker build -t secure-transport .

# ===== 步骤2: 停止并删除旧容器（如存在） =====
docker stop netsec-receiver 2>/dev/null || true
docker rm netsec-receiver 2>/dev/null || true

# ===== 步骤3: 启动接收端容器 =====
docker run -d \
  --name netsec-receiver \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --restart unless-stopped \
  -v /root/captured_data:/app/captured_data \
  -e MODE=receiver \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5000 \
  -e LISTEN_PORT=9999 \
  -e RSA_BITS=1024 \
  -e DATA_DIR=/app/captured_data \
  ghcr.io/gxfdev/secure-channel:latest

# ===== 步骤4: 验证容器运行状态 =====
docker ps | grep netsec-receiver
# 预期输出:
# CONTAINER ID   IMAGE                              STATUS          PORTS     NAMES
# xxxxxxxxxxxx   ghcr.io/gxfdev/secure-channel:...  Up 10 seconds             netsec-receiver

# ===== 步骤5: 检查容器日志 =====
docker logs netsec-receiver --tail 20
# 预期输出包含:
#   * Running on http://0.0.0.0:5000
#   接收端模式已启动，监听端口: 9999

# ===== 步骤6: 验证端口监听 =====
ss -tlnp | grep -E '5000|9999'
# 预期输出:
# LISTEN  0  128  0.0.0.0:5000  0.0.0.0:*   (Flask Web)
# LISTEN  0  5    0.0.0.0:9999  0.0.0.0:*   (协商服务)

# ===== 步骤7: 浏览器访问 Web 界面 =====
# 在本地电脑浏览器打开:
# http://192.168.157.207:5000
# 应看到"安全传输系统"界面，模式显示为"接收端"
```

---

**node8 部署步骤（发送端 192.168.157.208）：**

```bash
# ===== 步骤1: 拉取镜像 =====
# 与 node7 相同，选择一种方式拉取
echo '你的GHCR_TOKEN' | docker login ghcr.io -u gxfdev --password-stdin
docker pull ghcr.io/gxfdev/secure-channel:latest

# ===== 步骤2: 停止并删除旧容器（如存在） =====
docker stop netsec-sender 2>/dev/null || true
docker rm netsec-sender 2>/dev/null || true

# ===== 步骤3: 启动发送端容器 =====
docker run -d \
  --name netsec-sender \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --restart unless-stopped \
  -v /root/captured_data:/app/captured_data \
  -e MODE=sender \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5000 \
  -e RECEIVER_HOST=192.168.157.207 \
  -e RECEIVER_PORT=9999 \
  -e RSA_BITS=1024 \
  -e DATA_DIR=/app/captured_data \
  ghcr.io/gxfdev/secure-channel:latest

# ===== 步骤4: 验证容器运行状态 =====
docker ps | grep netsec-sender
# 预期输出:
# CONTAINER ID   IMAGE                              STATUS          PORTS     NAMES
# xxxxxxxxxxxx   ghcr.io/gxfdev/secure-channel:...  Up 10 seconds             netsec-sender

# ===== 步骤5: 检查容器日志 =====
docker logs netsec-sender --tail 20
# 预期输出包含:
#   * Running on http://0.0.0.0:5000
#   发送端模式已启动，目标: 192.168.157.207:9999

# ===== 步骤6: 验证端口监听 =====
ss -tlnp | grep 5000
# 预期输出:
# LISTEN  0  128  0.0.0.0:5000  0.0.0.0:*   (Flask Web)
# 注意: 发送端不监听 9999，只有接收端才监听

# ===== 步骤7: 浏览器访问 Web 界面 =====
# 在本地电脑浏览器打开:
# http://192.168.157.208:5000
# 应看到"安全传输系统"界面，模式显示为"发送端"
```

---

**连接测试与验证：**

```bash
# ===== 在 node8 发送端 Web 界面操作 =====
# 1. 打开 http://192.168.157.208:5000
# 2. 点击"连接"按钮，发起与 node7 的密钥协商
# 3. 观察协商过程：
#    - RSA 公钥交换 ✓
#    - DH 公钥交换 + 签名验证 ✓
#    - 会话密钥派生 ✓
# 4. 输入测试消息 "Hello, 安全传输!"
# 5. 点击"发送"

# ===== 在 node7 接收端 Web 界面确认 =====
# 1. 打开 http://192.168.157.207:5000
# 2. 应看到接收到的消息 "Hello, 安全传输!"
# 3. 查看抓包面板，确认加密数据包详情

# ===== 命令行验证连接 =====
# 在 node7 上查看 TCP 连接:
ss -tnp | grep 9999
# 预期输出:
# ESTAB  0  0  192.168.157.207:9999  192.168.157.208:xxxxx

# 在 node8 上查看 TCP 连接:
ss -tnp | grep 9999
# 预期输出:
# ESTAB  0  0  192.168.157.208:xxxxx  192.168.157.207:9999
```

**常见问题排查：**

| 问题 | 原因 | 解决方法 |
|------|------|---------|
| 容器启动失败 | 端口被占用 | `ss -tlnp \| grep 5000` 查看占用进程，`kill` 或改 `FLASK_PORT` |
| 发送端连接不上接收端 | 防火墙拦截 | `firewall-cmd --add-port=9999/tcp --permanent && firewall-cmd --reload` |
| 发送端连接不上接收端 | 接收端容器未启动 | 在 node7 上 `docker ps` 确认容器运行 |
| 抓包无数据 | 缺少网络权限 | 确认 `--cap-add NET_ADMIN --cap-add NET_RAW` 参数 |
| 切换模式后连接失败 | 旧连接未释放 | 重启容器: `docker restart netsec-receiver` |
| 容器重启后数据丢失 | 未挂载数据卷 | 确认 `-v /root/captured_data:/app/captured_data` |

**容器管理常用命令：**

```bash
# 查看容器状态
docker ps -a | grep netsec

# 查看实时日志
docker logs -f netsec-receiver    # 接收端
docker logs -f netsec-sender      # 发送端

# 重启容器
docker restart netsec-receiver
docker restart netsec-sender

# 进入容器调试
docker exec -it netsec-receiver /bin/bash
docker exec -it netsec-sender /bin/bash

# 更新部署（拉取新镜像后重新启动）
docker pull ghcr.io/gxfdev/secure-channel:latest
docker stop netsec-receiver && docker rm netsec-receiver
# 然后重新执行 docker run 命令（见上方步骤3）

# 完全清理
docker stop netsec-receiver netsec-sender
docker rm netsec-receiver netsec-sender
docker rmi ghcr.io/gxfdev/secure-channel:latest
```

#### Docker Compose 部署

```yaml
# docker-compose.yml
version: '3.8'

# 镜像配置 - 从阿里云ACR拉取或本地构建
x-image: &default-image
  image: ${DOCKER_IMAGE:-crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs:latest}

services:
  # 发送端
  sender:
    <<: *default-image
    container_name: netsec-sender
    environment:
      - MODE=sender
      - RECEIVER_HOST=${RECEIVER_HOST:-127.0.0.1}
      - RECEIVER_PORT=9999
      - LISTEN_PORT=9999
      - FLASK_HOST=0.0.0.0
      - FLASK_PORT=5000
      - RSA_BITS=1024
    network_mode: host
    volumes:
      - sender_data:/app/captured_data
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped

  # 接收端
  receiver:
    <<: *default-image
    container_name: netsec-receiver
    environment:
      - MODE=receiver
      - LISTEN_PORT=9999
      - FLASK_HOST=0.0.0.0
      - FLASK_PORT=5001
      - RSA_BITS=1024
    network_mode: host
    volumes:
      - receiver_data:/app/captured_data
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped

volumes:
  sender_data:
  receiver_data:
```

```bash
# 使用 docker-compose 启动（默认从阿里云 ACR 拉取镜像）
RECEIVER_HOST=10.0.0.2 docker-compose up -d

# 或本地构建后启动
DOCKER_IMAGE=secure-transport docker-compose up -d
```

### 3、Jenkins CI/CD 流水线

#### 流水线架构

```
┌─────────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  拉取代码    │ →  │ 构建Docker   │ →  │ 推送镜像到    │ →  │ 部署到接收端  │ →  │ 部署到发送端  │
│  git pull   │    │ 镜像         │    │ GHCR         │    │ node7        │    │ node8        │
└─────────────┘    └─────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

#### Jenkinsfile 说明

```groovy
pipeline {
    agent any

    environment {
        DOCKER_USER = 'gxfdev'
        REPO_NAME = 'secure-channel'
        TAG = "${env.BUILD_NUMBER}"
        RECEIVER_IP = '192.168.157.207'   // 接收端 node7 的 IP
        SENDER_IP = '192.168.157.208'     // 发送端 node8 的 IP
        GHCR_PAT = credentials('github-ghcr-token')  // GitHub PAT 凭据
    }

    stages {
        // 阶段1: 从 GitHub 拉取最新代码
        stage('拉取代码') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/gxfdev/secure-channel.git',
                    credentialsId: 'github-cred'
            }
        }

        // 阶段2: 构建 Docker 镜像
        stage('构建 Docker 镜像') {
            steps {
                script {
                    docker.build("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}")
                }
            }
        }

        // 阶段3: 推送镜像到 GitHub Container Registry
        stage('推送镜像到 GitHub Container Registry') {
            steps {
                script {
                    docker.withRegistry('https://ghcr.io', 'github-ghcr-token') {
                        docker.image("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}").push()
                        docker.image("ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}").push("latest")
                    }
                }
            }
        }

        // 阶段4: SSH 部署到接收端 node7
        stage('部署到接收端 node7') {
            steps {
                sshPublisher(publishers: [
                    sshPublisherDesc(configName: 'node7', transfers: [
                        sshTransfer(execCommand: """
                            echo '${GHCR_PAT}' | docker login ghcr.io -u ${DOCKER_USER} --password-stdin
                            docker pull ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                            docker stop netsec-receiver || true
                            docker rm netsec-receiver || true
                            docker run -d \\
                              --name netsec-receiver \\
                              --network host \\
                              --cap-add NET_ADMIN --cap-add NET_RAW \\
                              -v /root/captured_data:/app/captured_data \\
                              -e MODE=receiver \\
                              -e FLASK_HOST=0.0.0.0 \\
                              -e LISTEN_PORT=9999 \\
                              ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                        """)
                    ])
                ])
            }
        }

        // 阶段5: SSH 部署到发送端 node8
        stage('部署到发送端 node8') {
            steps {
                sshPublisher(publishers: [
                    sshPublisherDesc(configName: 'node8', transfers: [
                        sshTransfer(execCommand: """
                            echo '${GHCR_PAT}' | docker login ghcr.io -u ${DOCKER_USER} --password-stdin
                            docker pull ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                            docker stop netsec-sender || true
                            docker rm netsec-sender || true
                            docker run -d \\
                              --name netsec-sender \\
                              --network host \\
                              --cap-add NET_ADMIN --cap-add NET_RAW \\
                              -v /root/captured_data:/app/captured_data \\
                              -e MODE=sender \\
                              -e RECEIVER_HOST=${RECEIVER_IP} \\
                              -e FLASK_HOST=0.0.0.0 \\
                              -e RECEIVER_PORT=9999 \\
                              ghcr.io/${DOCKER_USER}/${REPO_NAME}:${TAG}
                        """)
                    ])
                ])
            }
        }
    }

    post {
        success { echo '流水线执行成功！两个节点均已更新。' }
        failure { echo '流水线执行失败，请检查控制台输出。' }
    }
}
```

#### Jenkins 配置要求

| 配置项 | 说明 |
|-------|------|
| 凭据 `github-cred` | GitHub 用户名+密码/PAT，用于拉取代码 |
| 凭据 `github-ghcr-token` | GitHub PAT（Secret text），用于推送/拉取 GHCR 镜像 |
| SSH 节点 `node7` | 接收端服务器 SSH 连接配置（192.168.157.207） |
| SSH 节点 `node8` | 发送端服务器 SSH 连接配置（192.168.157.208） |
| 插件 `SSH Pipeline Steps` | 提供 `sshPublisher` 命令，用于远程部署 |

### 4、环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| MODE | 运行模式: sender / receiver | sender |
| RECEIVER_HOST | 对端IP地址（发送端使用） | 127.0.0.1 |
| RECEIVER_PORT | 对端端口（发送端使用） | 9999 |
| LISTEN_PORT | 监听端口（接收端使用） | 9999 |
| RSA_BITS | RSA密钥位数 | 1024 |
| DH_BITS | DH私钥位数 | 512 |
| FLASK_HOST | Web服务监听地址 | 0.0.0.0 |
| FLASK_PORT | Web服务端口 | 5000 |
| DATA_DIR | 抓包数据存储目录 | /app/captured_data |

### 5、本地开发运行

```bash
# 安装依赖
pip install -r requirements.txt

# 方式1: 直接运行（默认发送端模式）
python app.py

# 方式2: 通过环境变量指定模式
MODE=receiver python app.py

# 方式3: 在 Python 中设置环境变量后运行
export MODE=sender
export RECEIVER_HOST=10.0.0.2
python app.py
```