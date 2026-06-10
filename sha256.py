"""
SHA-256 哈希算法自实现
遵循 FIPS 180-4 标准，不依赖任何外部加密库
"""

# SHA-256 初始哈希值（前8个素数平方根的小数部分前32位）
INIT_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# SHA-256 轮常数（前64个素数立方根的小数部分前32位）
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

MASK32 = 0xFFFFFFFF


def _rotr(x, n):
    """32位循环右移"""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x, n):
    """32位逻辑右移"""
    return x >> n


def _ch(x, y, z):
    """选择函数: (x AND y) XOR (NOT x AND z)"""
    return (x & y) ^ ((~x) & z)


def _maj(x, y, z):
    """多数函数: (x AND y) XOR (x AND z) XOR (y AND z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def _pad_message(message):
    """对消息进行填充，使其长度为512位的整数倍"""
    msg_len = len(message)
    msg_bits = msg_len * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += msg_bits.to_bytes(8, 'big')
    return message


def sha256(message):
    """
    SHA-256 哈希算法主函数
    输入: bytes 类型的消息
    输出: bytes 类型的32字节哈希值
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    message = _pad_message(message)
    h0, h1, h2, h3, h4, h5, h6, h7 = INIT_HASH

    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(block[i * 4:(i + 1) * 4], 'big')
        for i in range(16, 64):
            w[i] = (_gamma1(w[i - 2]) + w[i - 7] + _gamma0(w[i - 15]) + w[i - 16]) & MASK32

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(64):
            t1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + w[i]) & MASK32
            t2 = (_sigma0(a) + _maj(a, b, c)) & MASK32
            h = g
            g = f
            f = e
            e = (d + t1) & MASK32
            d = c
            c = b
            b = a
            a = (t1 + t2) & MASK32

        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32
        h5 = (h5 + f) & MASK32
        h6 = (h6 + g) & MASK32
        h7 = (h7 + h) & MASK32

    return b''.join(x.to_bytes(4, 'big') for x in [h0, h1, h2, h3, h4, h5, h6, h7])


if __name__ == '__main__':
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ]
    print("SHA-256 自实现测试:")
    for msg, expected in test_cases:
        result = sha256(msg).hex()
        status = "PASS" if result == expected else "FAIL"
        print(f"[{status}] 输入: {msg!r}  期望: {expected[:20]}...  实际: {result[:20]}...")
