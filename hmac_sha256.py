"""
HMAC-SHA256 消息认证码自实现
遵循 RFC 2104 标准，基于自实现的 SHA-256
HMAC用于验证消息的完整性和真实性（既防篡改又防伪造）
原理: HMAC(K,m) = SHA256((K⊕opad) || SHA256((K⊕ipad) || m))
"""
from sha256 import sha256  # 导入自实现的SHA-256


def hmac_sha256(key, message):
    """
    HMAC-SHA256 计算
    遵循 RFC 2104: HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

    参数:
        key: bytes, 认证密钥（任意长度，会自动处理）
        message: bytes, 待认证的消息
    返回:
        bytes, 32字节的HMAC值
    """
    block_size = 64  # SHA-256 的块大小为64字节（512位）

    # 步骤1: 处理密钥长度
    if len(key) > block_size:  # 如果密钥超过64字节
        key = sha256(key)  # 先对密钥做SHA-256哈希，压缩为32字节
    if len(key) < block_size:  # 如果密钥不足64字节
        key = key + b'\x00' * (block_size - len(key))  # 右侧补零到64字节

    # 步骤2: 生成 ipad 和 opad
    # ipad = 密钥每个字节与0x36异或（0x36 = 00110110）
    # opad = 密钥每个字节与0x5c异或（0x5c = 01011100）
    ipad = bytes(k ^ 0x36 for k in key)  # 内部填充，用于内部哈希
    opad = bytes(k ^ 0x5c for k in key)  # 外部填充，用于外部哈希

    # 步骤3: 计算内部哈希 H((K' ⊕ ipad) || m)
    inner_hash = sha256(ipad + message)  # 将ipad和消息拼接后哈希

    # 步骤4: 计算最终哈希 H((K' ⊕ opad) || inner_hash)
    result = sha256(opad + inner_hash)  # 将opad和内部哈希拼接后再哈希

    return result  # 返回32字节的HMAC值


if __name__ == '__main__':
    # 测试用例，对照 RFC 4231 中的测试向量
    print("HMAC-SHA256 自实现测试")
    print("=" * 60)

    # RFC 4231 Test Case 2
    key = b"Jefe"  # 测试密钥
    data = b"what do ya want for nothing?"  # 测试消息
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"  # 期望结果

    result = hmac_sha256(key, data).hex()  # 计算HMAC并转为十六进制
    status = "PASS" if result == expected else "FAIL"  # 与标准结果对比
    print(f"测试1 [{status}]:")
    print(f"  密钥: {key}")
    print(f"  消息: {data}")
    print(f"  期望: {expected}")
    print(f"  实际: {result}")
    print()

    # 简单功能测试
    key2 = b"secret_key_123"
    msg2 = b"Hello, HMAC-SHA256!"
    mac = hmac_sha256(key2, msg2)  # 计算HMAC
    print(f"测试2:")
    print(f"  密钥: {key2}")
    print(f"  消息: {msg2}")
    print(f"  HMAC: {mac.hex()}")

    # 验证: 相同输入应产生相同输出（确定性）
    mac2 = hmac_sha256(key2, msg2)
    print(f"  一致性验证: {'PASS' if mac == mac2 else 'FAIL'}")

    # 验证: 不同消息应产生不同输出（抗碰撞性）
    mac3 = hmac_sha256(key2, b"different message")
    print(f"  差异性验证: {'PASS' if mac != mac3 else 'FAIL'}")
