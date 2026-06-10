"""
RSA 公钥加密算法自实现
包含: Miller-Rabin 素性检测、密钥生成、加密、解密
"""
import random


def _gcd(a, b):
    """欧几里得算法求最大公约数"""
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a, m):
    """求模逆元"""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"模逆元不存在: gcd({a}, {m}) = {g}")
    return x % m


def _miller_rabin(n, k=20):
    """Miller-Rabin 素性检测"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits):
    """生成指定位数的随机大素数"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if _miller_rabin(n, k=20):
            return n


def generate_keypair(bits=512):
    """
    生成 RSA 密钥对
    返回: ((e, n), (d, n)) - 公钥和私钥
    """
    print(f"  正在生成 {bits} 位 RSA 密钥对...")
    half_bits = bits // 2
    p = _generate_prime(half_bits)
    q = _generate_prime(half_bits)
    while p == q:
        q = _generate_prime(half_bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    if _gcd(e, phi_n) != 1:
        e = 3
        while _gcd(e, phi_n) != 1:
            e += 2
    d = mod_inverse(e, phi_n)
    print(f"  RSA 密钥对生成完成！n 位数: {n.bit_length()}")
    return (e, n), (d, n)


def rsa_encrypt(message_int, public_key):
    """RSA 加密: c = m^e mod n"""
    e, n = public_key
    if message_int >= n:
        raise ValueError("消息值大于模数n，无法加密")
    return pow(message_int, e, n)


def rsa_decrypt(ciphertext_int, private_key):
    """RSA 解密: m = c^d mod n"""
    d, n = private_key
    return pow(ciphertext_int, d, n)


def rsa_encrypt_bytes(data, public_key):
    """RSA 加密字节序列"""
    e, n = public_key
    m = int.from_bytes(data, 'big')
    if m >= n:
        raise ValueError(f"数据过长({m.bit_length()}位)，无法用RSA({n.bit_length()}位)加密")
    c = rsa_encrypt(m, public_key)
    byte_len = (n.bit_length() + 7) // 8
    return c.to_bytes(byte_len, 'big')


def rsa_decrypt_bytes(data, private_key):
    """RSA 解密字节序列"""
    d, n = private_key
    c = int.from_bytes(data, 'big')
    m = rsa_decrypt(c, private_key)
    byte_len = max(1, (m.bit_length() + 7) // 8)
    return m.to_bytes(byte_len, 'big')


def rsa_sign(message_bytes, private_key):
    """
    RSA 数字签名: s = hash(m)^d mod n
    先对消息计算 SHA-256 哈希，再用私钥签名
    返回签名字节序列
    """
    from sha256 import sha256
    d, n = private_key
    # 计算消息哈希
    msg_hash = sha256(message_bytes)
    # 将哈希值转为整数
    h = int.from_bytes(msg_hash, 'big')
    if h >= n:
        raise ValueError("哈希值大于模数n")
    # 签名: h^d mod n
    signature = pow(h, d, n)
    byte_len = (n.bit_length() + 7) // 8
    return signature.to_bytes(byte_len, 'big')


def rsa_verify(message_bytes, signature_bytes, public_key):
    """
    RSA 签名验证:
    1. 计算 h' = s^e mod n
    2. 计算 h = SHA-256(message)
    3. 比较 h' == h
    返回 True/False
    """
    from sha256 import sha256
    e, n = public_key
    # 从签名恢复哈希值
    s = int.from_bytes(signature_bytes, 'big')
    recovered_hash = pow(s, e, n)
    # 计算消息的实际哈希
    actual_hash = int.from_bytes(sha256(message_bytes), 'big')
    return recovered_hash == actual_hash


def save_keypair(pub_key, priv_key, prefix="rsa_key"):
    """将 RSA 密钥对保存到文件"""
    e, n = pub_key
    d, _ = priv_key

    pub_data = f"RSA Public Key\n{'='*40}\ne = {e}\nn = {n}\nn_bits = {n.bit_length()}\n"
    with open(f"{prefix}_pub.pem", 'w') as f:
        f.write(pub_data)

    priv_data = f"RSA Private Key\n{'='*40}\nd = {d}\nn = {n}\nn_bits = {n.bit_length()}\n"
    with open(f"{prefix}_priv.pem", 'w') as f:
        f.write(priv_data)

    return f"{prefix}_pub.pem", f"{prefix}_priv.pem"


def load_keypair(prefix="rsa_key"):
    """从文件加载 RSA 密钥对"""
    with open(f"{prefix}_pub.pem", 'r') as f:
        lines = f.readlines()
        e = int(lines[2].split('= ')[1])
        n = int(lines[3].split('= ')[1])

    with open(f"{prefix}_priv.pem", 'r') as f:
        lines = f.readlines()
        d = int(lines[2].split('= ')[1])

    return (e, n), (d, n)


if __name__ == '__main__':
    print("RSA 自实现测试")
    print("=" * 60)
    pub_key, priv_key = generate_keypair(512)
    e, n = pub_key
    d, _ = priv_key
    print(f"公钥 (e={e}, n={n.bit_length()}位)")
    # 测试整数加解密
    message = 123456789
    cipher = rsa_encrypt(message, pub_key)
    decrypted = rsa_decrypt(cipher, priv_key)
    print(f"整数加解密: {'PASS' if decrypted == message else 'FAIL'}")
    # 测试字节加解密
    test_data = b"AES_KEY_16bytes"
    encrypted = rsa_encrypt_bytes(test_data, pub_key)
    decrypted_data = rsa_decrypt_bytes(encrypted, priv_key)
    print(f"字节加解密: {'PASS' if decrypted_data == test_data else 'FAIL'}")
