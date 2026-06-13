"""
AES-128 对称加密算法自实现
遵循 FIPS-197 标准，支持 ECB 和 CBC 模式，PKCS7 填充
AES-128: 密钥16字节(128位)，加密块16字节，10轮变换
安全性: 暴力破解2^128种可能密钥，目前计算能力下不可行
"""

# AES S-Box (FIPS-197标准替换盒)
# S-Box是一个256字节的查找表，用于SubBytes步骤的非线性替换
# 它提供了AES的"混淆"特性——使输入和输出之间的关系尽可能复杂
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# 逆S-Box（用于解密，是S-Box的逆映射）
INV_S_BOX = [0]*256
for _i in range(256):
    INV_S_BOX[S_BOX[_i]] = _i  # S_BOX[x]=y → INV_S_BOX[y]=x

# 轮常数Rcon（用于密钥扩展，每轮异或不同的常数）
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    """GF(2^8) 有限域乘法（伽罗瓦域乘法）
    AES中MixColumns步骤使用GF(2^8)域上的乘法
    特殊之处: 多项式乘法后要对不可约多项式x^8+x^4+x^3+x+1取模
    """
    p = 0  # 乘积结果
    for _ in range(8):  # 逐位处理
        if b & 1:  # 如果b的最低位为1
            p ^= a  # 将a异或到结果中（相当于加法，因为GF(2^8)中加法=异或）
        hi = a & 0x80  # 检查a的最高位是否为1
        a = (a << 1) & 0xff  # a左移1位，保留8位
        if hi:  # 如果最高位为1（溢出）
            a ^= 0x1b  # 异或不可约多项式x^8+x^4+x^3+x+1的低8位(0x1b)
        b >>= 1  # b右移1位，处理下一位
    return p


def _bytes_to_state(data):
    """16字节 → 4x4状态矩阵（AES使用列优先存储）
    状态矩阵: 4行4列，每列是一个32位字
    """
    state = [[0]*4 for _ in range(4)]  # 创建4x4矩阵
    for i in range(16):  # 遍历16个字节
        state[i % 4][i // 4] = data[i]  # 列优先填充：行=字节索引%4，列=字节索引//4
    return state


def _state_to_bytes(state):
    """4x4状态矩阵 → 16字节（列优先读取）"""
    result = bytearray(16)  # 创建16字节数组
    for i in range(16):  # 遍历16个位置
        result[i] = state[i % 4][i // 4]  # 列优先读取
    return bytes(result)


def _sub_bytes(state):
    """SubBytes: 对状态矩阵的每个字节进行S-Box替换（非线性变换，提供混淆性）"""
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state):
    """逆SubBytes: 对状态矩阵的每个字节进行逆S-Box替换（解密用）"""
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    """ShiftRows: 对状态矩阵的行进行循环左移（提供扩散性）
    第0行不移，第1行左移1，第2行左移2，第3行左移3
    """
    return [
        state[0][:],  # 第0行：不移动
        state[1][1:] + state[1][:1],  # 第1行：左移1字节
        state[2][2:] + state[2][:2],  # 第2行：左移2字节
        state[3][3:] + state[3][:3],  # 第3行：左移3字节
    ]


def _inv_shift_rows(state):
    """逆ShiftRows: 对状态矩阵的行进行循环右移（解密用）"""
    return [
        state[0][:],  # 第0行：不移动
        state[1][3:] + state[1][:3],  # 第1行：右移1字节
        state[2][2:] + state[2][:2],  # 第2行：右移2字节
        state[3][1:] + state[3][:1],  # 第3行：右移3字节
    ]


def _mix_columns(state):
    """MixColumns: 对状态矩阵的每列进行GF(2^8)矩阵乘法（提供扩散性）
    固定矩阵: [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
    """
    result = [[0]*4 for _ in range(4)]  # 结果矩阵
    for c in range(4):  # 对每列进行变换
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]  # 取出当前列
        # 矩阵乘法（GF(2^8)域上）
        result[0][c] = _gmul(2, s0) ^ _gmul(3, s1) ^ s2 ^ s3  # 2*s0 + 3*s1 + s2 + s3
        result[1][c] = s0 ^ _gmul(2, s1) ^ _gmul(3, s2) ^ s3  # s0 + 2*s1 + 3*s2 + s3
        result[2][c] = s0 ^ s1 ^ _gmul(2, s2) ^ _gmul(3, s3)  # s0 + s1 + 2*s2 + 3*s3
        result[3][c] = _gmul(3, s0) ^ s1 ^ s2 ^ _gmul(2, s3)  # 3*s0 + s1 + s2 + 2*s3
    return result


def _inv_mix_columns(state):
    """逆MixColumns: 对状态矩阵的每列进行逆GF(2^8)矩阵乘法（解密用）
    逆矩阵: [14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14]
    """
    result = [[0]*4 for _ in range(4)]  # 结果矩阵
    for c in range(4):  # 对每列进行逆变换
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        # 逆矩阵乘法
        result[0][c] = _gmul(14, s0) ^ _gmul(11, s1) ^ _gmul(13, s2) ^ _gmul(9, s3)
        result[1][c] = _gmul(9, s0) ^ _gmul(14, s1) ^ _gmul(11, s2) ^ _gmul(13, s3)
        result[2][c] = _gmul(13, s0) ^ _gmul(9, s1) ^ _gmul(14, s2) ^ _gmul(11, s3)
        result[3][c] = _gmul(11, s0) ^ _gmul(13, s1) ^ _gmul(9, s2) ^ _gmul(14, s3)
    return result


def _add_round_key(state, round_key):
    """AddRoundKey: 状态矩阵与轮密钥逐字节异或（引入密钥信息）"""
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def _sub_word(word):
    """对4字节字进行S-Box替换（密钥扩展用）"""
    return [S_BOX[b] for b in word]


def _rot_word(word):
    """对4字节字进行循环左移1字节（密钥扩展用）"""
    return word[1:] + word[:1]


def key_expansion(key):
    """AES-128 密钥扩展: 16字节(128位)密钥 → 11组轮密钥(每组4x4=16字节)
    AES-128需要10轮加密+1次初始AddRoundKey，共11组轮密钥
    """
    w = []  # 扩展密钥字数组，每个字4字节，共44个字
    for i in range(4):  # 前4个字直接从原始密钥取
        w.append(list(key[i*4:(i+1)*4]))
    for i in range(4, 44):  # 扩展剩余40个字
        temp = w[i-1][:]  # 取前一个字
        if i % 4 == 0:  # 每4个字进行一次特殊处理
            temp = _sub_word(_rot_word(temp))  # 先循环左移，再S-Box替换
            temp[0] ^= RCON[i // 4]  # 第一个字节异或轮常数
        # W[i] = W[i-4] XOR temp
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    # 将44个字组织为11组轮密钥（每组4个字=16字节）
    round_keys = []
    for r in range(11):  # 11组轮密钥
        rk = [[0]*4 for _ in range(4)]  # 4x4矩阵
        for c in range(4):  # 每列
            for row in range(4):  # 每行
                rk[row][c] = w[r*4 + c][row]  # 字节重组为状态矩阵格式
        round_keys.append(rk)
    return round_keys


def _pkcs7_pad(data, block_size=16):
    """PKCS7填充: 在数据末尾填充N个值为N的字节，使总长度为block_size的整数倍
    例: 数据差3字节 → 填充 [0x03, 0x03, 0x03]
    """
    pad_len = block_size - (len(data) % block_size)  # 计算需要填充的字节数
    return data + bytes([pad_len] * pad_len)  # 填充pad_len个值为pad_len的字节


def _pkcs7_unpad(data):
    """PKCS7去填充: 读取最后一个字节的值N，去掉末尾N个字节"""
    pad_len = data[-1]  # 最后一个字节的值就是填充长度
    if pad_len < 1 or pad_len > 16:  # 填充值必须在1-16之间
        raise ValueError(f"无效的PKCS7填充值: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):  # 验证填充是否正确
        raise ValueError("PKCS7填充验证失败")
    return data[:-pad_len]  # 去掉填充字节


def _aes_encrypt_block(block, round_keys):
    """AES-128 单块(16字节)加密
    流程: AddRoundKey(0) → [SubBytes → ShiftRows → MixColumns → AddRoundKey] × 9轮 → SubBytes → ShiftRows → AddRoundKey(10)
    """
    state = _bytes_to_state(block)  # 将16字节转为4x4状态矩阵
    state = _add_round_key(state, round_keys[0])  # 初始轮密钥加
    for r in range(1, 10):  # 第1~9轮（9轮完整变换）
        state = _sub_bytes(state)  # 字节替换
        state = _shift_rows(state)  # 行移位
        state = _mix_columns(state)  # 列混合
        state = _add_round_key(state, round_keys[r])  # 轮密钥加
    # 第10轮（没有MixColumns）
    state = _sub_bytes(state)  # 字节替换
    state = _shift_rows(state)  # 行移位
    state = _add_round_key(state, round_keys[10])  # 最终轮密钥加
    return _state_to_bytes(state)  # 状态矩阵转回16字节


def _aes_decrypt_block(block, round_keys):
    """AES-128 单块(16字节)解密（加密的逆过程）
    流程: AddRoundKey(10) → [InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns] × 9轮 → InvShiftRows → InvSubBytes → AddRoundKey(0)
    """
    state = _bytes_to_state(block)  # 将16字节转为4x4状态矩阵
    state = _add_round_key(state, round_keys[10])  # 初始轮密钥加（用第10轮密钥）
    for r in range(9, 0, -1):  # 第9~1轮（逆序）
        state = _inv_shift_rows(state)  # 逆行移位
        state = _inv_sub_bytes(state)  # 逆字节替换
        state = _add_round_key(state, round_keys[r])  # 轮密钥加
        state = _inv_mix_columns(state)  # 逆列混合
    # 最后一轮（没有InvMixColumns）
    state = _inv_shift_rows(state)  # 逆行移位
    state = _inv_sub_bytes(state)  # 逆字节替换
    state = _add_round_key(state, round_keys[0])  # 最终轮密钥加（用第0轮密钥）
    return _state_to_bytes(state)  # 状态矩阵转回16字节


def aes_encrypt(plaintext, key, mode='ecb', iv=None):
    """
    AES-128 加密（支持ECB和CBC模式）
    参数:
        plaintext: bytes, 明文（任意长度）
        key: bytes, 16字节密钥
        mode: 'ecb' 或 'cbc'
        iv: bytes, 16字节初始化向量（CBC模式必需）
    返回: (ciphertext, iv)
    ECB模式: 每个块独立加密，相同明文块→相同密文块（不安全，仅教学用）
    CBC模式: 每个明文块先与前一个密文块异或再加密（安全，推荐）
    """
    if len(key) != 16:  # AES-128密钥必须是16字节
        raise ValueError("AES-128 密钥长度必须为16字节")
    round_keys = key_expansion(key)  # 扩展密钥
    padded = _pkcs7_pad(plaintext)  # PKCS7填充
    # CBC模式需要初始化向量IV
    if mode == 'cbc':
        if iv is None:  # 如果未提供IV，随机生成16字节
            iv = __import__('os').urandom(16)
        if len(iv) != 16:  # IV必须是16字节
            raise ValueError("IV 长度必须为16字节")
    else:
        iv = None  # ECB模式不需要IV
    ciphertext = b''  # 密文结果
    prev = iv  # 前一个密文块（CBC模式用）
    for i in range(0, len(padded), 16):  # 逐块加密
        block = padded[i:i+16]  # 取16字节块
        if mode == 'cbc' and prev is not None:  # CBC模式
            block = bytes(a ^ b for a, b in zip(block, prev))  # 明文块与前一个密文块异或
        encrypted = _aes_encrypt_block(block, round_keys)  # AES加密
        ciphertext += encrypted  # 追加密文
        prev = encrypted  # 更新前一个密文块
    return ciphertext, iv  # 返回密文和IV


def aes_decrypt(ciphertext, key, mode='ecb', iv=None):
    """
    AES-128 解密（支持ECB和CBC模式）
    参数:
        ciphertext: bytes, 密文
        key: bytes, 16字节密钥
        mode: 'ecb' 或 'cbc'
        iv: bytes, 16字节初始化向量（CBC模式必需）
    返回: bytes 明文
    """
    if len(key) != 16:  # AES-128密钥必须是16字节
        raise ValueError("AES-128 密钥长度必须为16字节")
    if len(ciphertext) % 16 != 0:  # 密文长度必须是16的整数倍
        raise ValueError("密文长度必须是16的整数倍")
    round_keys = key_expansion(key)  # 扩展密钥
    plaintext = b''  # 明文结果
    prev = iv  # 前一个密文块（CBC模式用）
    for i in range(0, len(ciphertext), 16):  # 逐块解密
        block = ciphertext[i:i+16]  # 取16字节密文块
        decrypted = _aes_decrypt_block(block, round_keys)  # AES解密
        if mode == 'cbc' and prev is not None:  # CBC模式
            decrypted = bytes(a ^ b for a, b in zip(decrypted, prev))  # 与前一个密文块异或
        plaintext += decrypted  # 追加明文
        prev = block  # 更新前一个密文块（注意：这里用的是密文块，不是解密后的明文）
    return _pkcs7_unpad(plaintext)  # 去掉PKCS7填充


if __name__ == '__main__':
    # AES-128标准测试向量
    import os
    print("AES-128 自实现测试")
    print("=" * 60)
    # FIPS-197 标准测试向量
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # 标准测试密钥
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")  # 标准测试明文
    ct, _ = aes_encrypt(plaintext, key, mode='ecb')  # ECB加密
    expected = "3ad77bb40d7a3660a89ecaf32466ef97"  # 期望密文
    print(f"ECB加密: {'PASS' if ct.hex() == expected else 'FAIL'}")
    pt = aes_decrypt(ct, key, mode='ecb')  # ECB解密
    print(f"ECB解密: {'PASS' if pt == plaintext else 'FAIL'}")
    # CBC模式测试
    key2 = os.urandom(16)  # 随机密钥
    iv = os.urandom(16)  # 随机IV
    msg = b"Hello, AES-128-CBC mode test!"
    ct2, iv2 = aes_encrypt(msg, key2, mode='cbc', iv=iv)  # CBC加密
    pt2 = aes_decrypt(ct2, key2, mode='cbc', iv=iv2)  # CBC解密
    print(f"CBC模式: {'PASS' if pt2 == msg else 'FAIL'}")
