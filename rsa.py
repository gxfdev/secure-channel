"""
RSA 公钥加密算法自实现
包含: Miller-Rabin 素性检测、密钥生成、加密、解密、数字签名
"""
import random  # 导入随机数模块，用于生成大素数和素性检测


def _gcd(a, b):
    """欧几里得算法求最大公约数（用于判断两个数是否互素）"""
    while b:  # 当b不为0时继续循环
        a, b = b, a % b  # 辗转相除：a取b的值，b取a除以b的余数
    return a  # 当b为0时，a就是最大公约数


def _extended_gcd(a, b):
    """扩展欧几里得算法（求ax+by=gcd(a,b)的整数解x,y）"""
    if a == 0:  # 递归终止条件
        return b, 0, 1  # gcd(0,b)=b, x=0, y=1
    g, x, y = _extended_gcd(b % a, a)  # 递归求解
    return g, y - (b // a) * x, x  # 根据递归结果计算x,y


def mod_inverse(a, m):
    """求a关于模m的模逆元（即求x使得 a*x ≡ 1 (mod m)）"""
    g, x, _ = _extended_gcd(a % m, m)  # 用扩展欧几里得算法
    if g != 1:  # 如果gcd(a,m)≠1，模逆元不存在
        raise ValueError(f"模逆元不存在: gcd({a}, {m}) = {g}")
    return x % m  # 确保结果为正数


def _miller_rabin(n, k=20):
    """
    Miller-Rabin 素性检测（概率性检测，k=20时错误概率<2^-40）
    原理：如果n是素数，则对于某些a，a^(n-1) ≡ 1 (mod n)
    """
    if n < 2:  # 小于2的数不是素数
        return False
    if n == 2 or n == 3:  # 2和3是素数
        return True
    if n % 2 == 0:  # 偶数不是素数
        return False
    # 将n-1分解为 2^s * d（d是奇数）
    s, d = 0, n - 1
    while d % 2 == 0:  # 不断除以2直到d为奇数
        d //= 2
        s += 1
    # 进行k轮检测
    for _ in range(k):
        a = random.randrange(2, n - 1)  # 随机选择基数a
        x = pow(a, d, n)  # 计算 a^d mod n
        if x == 1 or x == n - 1:  # 如果x=1或x=n-1，这轮检测通过
            continue
        # 反复平方检测
        for _ in range(s - 1):
            x = pow(x, 2, n)  # 计算 x^2 mod n
            if x == n - 1:  # 如果x=n-1，这轮检测通过
                break
        else:  # 如果所有平方都不等于n-1，n是合数
            return False
    return True  # 通过所有k轮检测，n很可能是素数


def _generate_prime(bits):
    """生成指定位数的随机大素数"""
    while True:  # 不断尝试直到找到素数
        n = random.getrandbits(bits)  # 生成bits位随机数
        n |= (1 << (bits - 1)) | 1  # 确保最高位和最低位为1（保证位数和奇数）
        if _miller_rabin(n, k=20):  # Miller-Rabin检测
            return n


def generate_keypair(bits=512):
    """
    生成 RSA 密钥对
    参数: bits - 密钥位数（默认512位，教学用途）
    返回: ((e, n), (d, n)) - 公钥和私钥
    流程: 1.生成两个大素数p,q → 2.计算n=p*q → 3.计算φ(n)=(p-1)(q-1) → 4.选e → 5.算d=e^(-1) mod φ(n)
    """
    print(f"  正在生成 {bits} 位 RSA 密钥对...")
    half_bits = bits // 2  # 每个素数占一半位数
    p = _generate_prime(half_bits)  # 生成素数p
    q = _generate_prime(half_bits)  # 生成素数q
    while p == q:  # 确保p≠q
        q = _generate_prime(half_bits)
    n = p * q  # 计算模数n = p * q
    phi_n = (p - 1) * (q - 1)  # 计算欧拉函数φ(n) = (p-1)(q-1)
    e = 65537  # 公钥指数e，通常取65537（2^16+1，费马素数）
    if _gcd(e, phi_n) != 1:  # 如果65537与φ(n)不互素
        e = 3  # 从3开始尝试
        while _gcd(e, phi_n) != 1:  # 找到与φ(n)互素的e
            e += 2  # 只尝试奇数（偶数一定与φ(n)不互素）
    d = mod_inverse(e, phi_n)  # 计算私钥指数d = e^(-1) mod φ(n)
    print(f"  RSA 密钥对生成完成！n 位数: {n.bit_length()}")
    return (e, n), (d, n)  # 返回公钥(e,n)和私钥(d,n)


def rsa_encrypt(message_int, public_key):
    """RSA 加密: c = m^e mod n（m是明文整数，c是密文整数）"""
    e, n = public_key  # 解包公钥
    if message_int >= n:  # 明文必须小于模数n
        raise ValueError("消息值大于模数n，无法加密")
    return pow(message_int, e, n)  # 计算m^e mod n


def rsa_decrypt(ciphertext_int, private_key):
    """RSA 解密: m = c^d mod n（c是密文整数，m是明文整数）"""
    d, n = private_key  # 解包私钥
    return pow(ciphertext_int, d, n)  # 计算c^d mod n


def rsa_encrypt_bytes(data, public_key):
    """RSA 加密字节序列（将字节转整数→加密→转回字节）"""
    e, n = public_key  # 解包公钥
    m = int.from_bytes(data, 'big')  # 字节序列转大端序整数
    if m >= n:  # 数据不能超过模数n
        raise ValueError(f"数据过长({m.bit_length()}位)，无法用RSA({n.bit_length()}位)加密")
    c = rsa_encrypt(m, public_key)  # RSA加密
    byte_len = (n.bit_length() + 7) // 8  # 计算n的字节长度
    return c.to_bytes(byte_len, 'big')  # 整数转字节序列，固定长度


def rsa_decrypt_bytes(data, private_key):
    """RSA 解密字节序列（将字节转整数→解密→转回字节）"""
    d, n = private_key  # 解包私钥
    c = int.from_bytes(data, 'big')  # 字节序列转大端序整数
    m = rsa_decrypt(c, private_key)  # RSA解密
    byte_len = max(1, (m.bit_length() + 7) // 8)  # 计算明文字节长度
    return m.to_bytes(byte_len, 'big')  # 整数转字节序列


def rsa_sign(message_bytes, private_key):
    """
    RSA 数字签名: s = SHA256(m)^d mod n
    先对消息计算SHA-256哈希，再用私钥对哈希值签名
    签名保证：1.身份认证（只有私钥持有者能签名）2.完整性（哈希值唯一）3.不可否认性
    """
    from sha256 import sha256  # 使用自实现的SHA-256
    d, n = private_key  # 解包私钥
    msg_hash = sha256(message_bytes)  # 计算消息的SHA-256哈希（32字节）
    h = int.from_bytes(msg_hash, 'big')  # 哈希值转整数
    if h >= n:  # 哈希值必须小于模数n
        raise ValueError("哈希值大于模数n")
    signature = pow(h, d, n)  # 签名: h^d mod n（用私钥加密哈希值）
    byte_len = (n.bit_length() + 7) // 8  # 计算签名字节长度
    return signature.to_bytes(byte_len, 'big')  # 签名转字节序列


def rsa_verify(message_bytes, signature_bytes, public_key):
    """
    RSA 签名验证:
    1. 从签名恢复哈希值: h' = s^e mod n（用公钥解密签名）
    2. 计算消息的实际哈希: h = SHA-256(message)
    3. 比较 h' == h，相等则签名有效
    """
    from sha256 import sha256  # 使用自实现的SHA-256
    e, n = public_key  # 解包公钥
    s = int.from_bytes(signature_bytes, 'big')  # 签名转整数
    recovered_hash = pow(s, e, n)  # 用公钥解密签名，恢复哈希值: s^e mod n
    actual_hash = int.from_bytes(sha256(message_bytes), 'big')  # 计算消息的实际哈希
    return recovered_hash == actual_hash  # 比较恢复的哈希和实际哈希是否相同


def save_keypair(pub_key, priv_key, prefix="rsa_key"):
    """将 RSA 密钥对保存到文件（文本格式）"""
    e, n = pub_key  # 解包公钥
    d, _ = priv_key  # 解包私钥

    # 构建公钥文件内容
    pub_data = f"RSA Public Key\n{'='*40}\ne = {e}\nn = {n}\nn_bits = {n.bit_length()}\n"
    with open(f"{prefix}_pub.pem", 'w') as f:  # 写入公钥文件
        f.write(pub_data)

    # 构建私钥文件内容
    priv_data = f"RSA Private Key\n{'='*40}\nd = {d}\nn = {n}\nn_bits = {n.bit_length()}\n"
    with open(f"{prefix}_priv.pem", 'w') as f:  # 写入私钥文件
        f.write(priv_data)

    return f"{prefix}_pub.pem", f"{prefix}_priv.pem"  # 返回文件路径


def load_keypair(prefix="rsa_key"):
    """从文件加载 RSA 密钥对"""
    with open(f"{prefix}_pub.pem", 'r') as f:  # 读取公钥文件
        lines = f.readlines()
        e = int(lines[2].split('= ')[1])  # 解析e值
        n = int(lines[3].split('= ')[1])  # 解析n值

    with open(f"{prefix}_priv.pem", 'r') as f:  # 读取私钥文件
        lines = f.readlines()
        d = int(lines[2].split('= ')[1])  # 解析d值

    return (e, n), (d, n)  # 返回公钥和私钥


if __name__ == '__main__':
    # RSA测试代码
    print("RSA 自实现测试")
    print("=" * 60)
    pub_key, priv_key = generate_keypair(512)  # 生成512位RSA密钥对
    e, n = pub_key
    d, _ = priv_key
    print(f"公钥 (e={e}, n={n.bit_length()}位)")
    # 测试整数加解密
    message = 123456789
    cipher = rsa_encrypt(message, pub_key)  # 加密
    decrypted = rsa_decrypt(cipher, priv_key)  # 解密
    print(f"整数加解密: {'PASS' if decrypted == message else 'FAIL'}")
    # 测试字节加解密
    test_data = b"AES_KEY_16bytes"
    encrypted = rsa_encrypt_bytes(test_data, pub_key)  # 加密字节
    decrypted_data = rsa_decrypt_bytes(encrypted, priv_key)  # 解密字节
    print(f"字节加解密: {'PASS' if decrypted_data == test_data else 'FAIL'}")
