"""
SHA-256 哈希算法自实现
遵循 FIPS 180-4 标准，不依赖任何外部加密库
SHA-256将任意长度的消息压缩为固定256位(32字节)的哈希值
特点: 单向性(不可逆)、抗碰撞性(找不到两个不同消息有相同哈希)、雪崩效应(微小改变导致哈希巨变)
"""

# SHA-256 初始哈希值H0~H7（前8个素数2,3,5,7,11,13,17,19的平方根小数部分前32位）
INIT_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,  # H0~H3
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19   # H4~H7
]

# SHA-256 轮常数K0~K63（前64个素数的立方根小数部分前32位）
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  # K0~K3
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,  # K4~K7
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2   # K60~K63
]

# 32位掩码，用于确保所有运算在32位范围内
MASK32 = 0xFFFFFFFF


def _rotr(x, n):
    """32位循环右移（右侧移出的位从左侧补回）"""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x, n):
    """32位逻辑右移（右侧移出的位丢弃，左侧补0）"""
    return x >> n


def _ch(x, y, z):
    """选择函数Ch: x的每位为1则选y对应位，为0则选z对应位"""
    return (x & y) ^ ((~x) & z)


def _maj(x, y, z):
    """多数函数Maj: 三个输入的对应位中，取多数值(0或1)"""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x):
    """大写Sigma0: ROTR(2) XOR ROTR(13) XOR ROTR(22)，用于压缩函数"""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x):
    """大写Sigma1: ROTR(6) XOR ROTR(11) XOR ROTR(25)，用于压缩函数"""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x):
    """小写sigma0: ROTR(7) XOR ROTR(18) XOR SHR(3)，用于消息调度"""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x):
    """小写sigma1: ROTR(17) XOR ROTR(19) XOR SHR(10)，用于消息调度"""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def _pad_message(message):
    """
    对消息进行填充，使其长度为512位(64字节)的整数倍
    填充规则: 1.追加0x80 2.追加0x00直到长度≡56(mod 64) 3.追加8字节原始消息长度(大端序)
    """
    msg_len = len(message)  # 原始消息字节数
    msg_bits = msg_len * 8  # 原始消息位数
    message += b'\x80'  # 追加1位'1'（即0x80 = 10000000）
    # 追加0x00直到长度≡56(mod 64)，留出8字节放消息长度
    while len(message) % 64 != 56:
        message += b'\x00'
    # 追加8字节的消息位长度（大端序64位整数）
    message += msg_bits.to_bytes(8, 'big')
    return message


def sha256(message):
    """
    SHA-256 哈希算法主函数
    输入: bytes 类型的消息
    输出: bytes 类型的32字节(256位)哈希值
    流程: 填充 → 分块(512位) → 消息调度(扩展为64个字) → 压缩(64轮) → 输出
    """
    # 如果输入是字符串，先转为UTF-8字节
    if isinstance(message, str):
        message = message.encode('utf-8')

    # 步骤1: 填充消息
    message = _pad_message(message)
    # 初始化8个工作变量为初始哈希值
    h0, h1, h2, h3, h4, h5, h6, h7 = INIT_HASH

    # 步骤2: 逐块处理（每块512位=64字节）
    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]  # 取出一个512位块
        # 步骤3: 消息调度——将16个字扩展为64个字
        w = [0] * 64  # 64个32位字的数组
        for i in range(16):  # 前16个字直接从消息块中取
            w[i] = int.from_bytes(block[i * 4:(i + 1) * 4], 'big')  # 每4字节一个字
        for i in range(16, 64):  # 后48个字通过公式计算
            # W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
            w[i] = (_gamma1(w[i - 2]) + w[i - 7] + _gamma0(w[i - 15]) + w[i - 16]) & MASK32

        # 步骤4: 压缩函数——64轮运算
        # 初始化工作变量a~h为当前哈希值
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(64):  # 64轮压缩
            # 计算两个中间变量
            t1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + w[i]) & MASK32  # T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
            t2 = (_sigma0(a) + _maj(a, b, c)) & MASK32  # T2 = Sigma0(a) + Maj(a,b,c)
            # 更新工作变量
            h = g  # h ← g
            g = f  # g ← f
            f = e  # f ← e
            e = (d + t1) & MASK32  # e ← d + T1
            d = c  # d ← c
            c = b  # c ← b
            b = a  # b ← a
            a = (t1 + t2) & MASK32  # a ← T1 + T2

        # 步骤5: 将压缩结果加到哈希值上
        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32
        h5 = (h5 + f) & MASK32
        h6 = (h6 + g) & MASK32
        h7 = (h7 + h) & MASK32

    # 步骤6: 将8个32位哈希值拼接为32字节输出
    return b''.join(x.to_bytes(4, 'big') for x in [h0, h1, h2, h3, h4, h5, h6, h7])


if __name__ == '__main__':
    # SHA-256标准测试向量
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),  # 空消息
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),  # "abc"
    ]
    print("SHA-256 自实现测试:")
    for msg, expected in test_cases:
        result = sha256(msg).hex()  # 计算哈希值并转为十六进制字符串
        status = "PASS" if result == expected else "FAIL"  # 与标准结果对比
        print(f"[{status}] 输入: {msg!r}  期望: {expected[:20]}...  实际: {result[:20]}...")
