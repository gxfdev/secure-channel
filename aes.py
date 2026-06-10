"""
AES-128 对称加密算法自实现
遵循 FIPS-197 标准，支持 ECB 和 CBC 模式，PKCS7 填充
"""

# AES S-Box (FIPS-197)
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

# 逆S-Box
INV_S_BOX = [0]*256
for _i in range(256):
    INV_S_BOX[S_BOX[_i]] = _i

# 轮常数
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    """GF(2^8) 乘法"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _bytes_to_state(data):
    """16字节 -> 4x4状态矩阵（列优先）"""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def _state_to_bytes(state):
    """4x4状态矩阵 -> 16字节"""
    result = bytearray(16)
    for i in range(16):
        result[i] = state[i % 4][i // 4]
    return bytes(result)


def _sub_bytes(state):
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state):
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    return [
        state[0][:],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]


def _inv_shift_rows(state):
    return [
        state[0][:],
        state[1][3:] + state[1][:3],
        state[2][2:] + state[2][:2],
        state[3][1:] + state[3][:1],
    ]


def _mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        result[0][c] = _gmul(2, s0) ^ _gmul(3, s1) ^ s2 ^ s3
        result[1][c] = s0 ^ _gmul(2, s1) ^ _gmul(3, s2) ^ s3
        result[2][c] = s0 ^ s1 ^ _gmul(2, s2) ^ _gmul(3, s3)
        result[3][c] = _gmul(3, s0) ^ s1 ^ s2 ^ _gmul(2, s3)
    return result


def _inv_mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        result[0][c] = _gmul(14, s0) ^ _gmul(11, s1) ^ _gmul(13, s2) ^ _gmul(9, s3)
        result[1][c] = _gmul(9, s0) ^ _gmul(14, s1) ^ _gmul(11, s2) ^ _gmul(13, s3)
        result[2][c] = _gmul(13, s0) ^ _gmul(9, s1) ^ _gmul(14, s2) ^ _gmul(11, s3)
        result[3][c] = _gmul(11, s0) ^ _gmul(13, s1) ^ _gmul(9, s2) ^ _gmul(14, s3)
    return result


def _add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def _sub_word(word):
    return [S_BOX[b] for b in word]


def _rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key):
    """AES-128 密钥扩展: 16字节密钥 -> 11组轮密钥"""
    w = []
    for i in range(4):
        w.append(list(key[i*4:(i+1)*4]))
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // 4]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = [[0]*4 for _ in range(4)]
        for c in range(4):
            for row in range(4):
                rk[row][c] = w[r*4 + c][row]
        round_keys.append(rk)
    return round_keys


def _pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"无效的PKCS7填充值: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS7填充验证失败")
    return data[:-pad_len]


def _aes_encrypt_block(block, round_keys):
    """AES-128 单块加密"""
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)


def _aes_decrypt_block(block, round_keys):
    """AES-128 单块解密"""
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def aes_encrypt(plaintext, key, mode='ecb', iv=None):
    """
    AES-128 加密
    参数: plaintext(bytes), key(bytes16), mode('ecb'/'cbc'), iv(bytes16)
    返回: (ciphertext, iv)
    """
    if len(key) != 16:
        raise ValueError("AES-128 密钥长度必须为16字节")
    round_keys = key_expansion(key)
    padded = _pkcs7_pad(plaintext)
    if mode == 'cbc':
        if iv is None:
            iv = __import__('os').urandom(16)
        if len(iv) != 16:
            raise ValueError("IV 长度必须为16字节")
    else:
        iv = None
    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        if mode == 'cbc' and prev is not None:
            block = bytes(a ^ b for a, b in zip(block, prev))
        encrypted = _aes_encrypt_block(block, round_keys)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext, iv


def aes_decrypt(ciphertext, key, mode='ecb', iv=None):
    """
    AES-128 解密
    参数: ciphertext(bytes), key(bytes16), mode('ecb'/'cbc'), iv(bytes16)
    返回: bytes 明文
    """
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
        prev = block
    return _pkcs7_unpad(plaintext)


if __name__ == '__main__':
    import os
    print("AES-128 自实现测试")
    print("=" * 60)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ct, _ = aes_encrypt(plaintext, key, mode='ecb')
    expected = "3ad77bb40d7a3660a89ecaf32466ef97"
    print(f"ECB加密: {'PASS' if ct.hex() == expected else 'FAIL'}")
    pt = aes_decrypt(ct, key, mode='ecb')
    print(f"ECB解密: {'PASS' if pt == plaintext else 'FAIL'}")
    # CBC模式测试
    key2 = os.urandom(16)
    iv = os.urandom(16)
    msg = b"Hello, AES-128-CBC mode test!"
    ct2, iv2 = aes_encrypt(msg, key2, mode='cbc', iv=iv)
    pt2 = aes_decrypt(ct2, key2, mode='cbc', iv=iv2)
    print(f"CBC模式: {'PASS' if pt2 == msg else 'FAIL'}")
