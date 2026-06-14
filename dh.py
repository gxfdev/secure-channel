"""
Diffie-Hellman 密钥协商算法自实现
遵循 RFC 3526 标准，使用 2048 位 MODP 素数群
"""
import random  # 导入随机数模块，用于生成DH私钥
import hashlib  # 导入哈希模块（备用，实际使用自实现的SHA-256）

# RFC 3526 2048-bit MODP Group (素数 p 和生成元 g)
# 这是一个公开的大素数，所有DH参与者都使用相同的p和g
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"  # 素数p的高位字节
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "DEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16  # 16进制字符串转为整数
)

# 生成元g，通常取2
DH_GENERATOR = 2


class DHPeer:
    """DH 密钥协商参与方"""

    def __init__(self, bits=512, prime=None, generator=None):
        """
        初始化DH参与方
        参数:
            bits: 私钥位数（默认512位，足够安全）
            prime: 自定义素数（None则使用RFC 3526）
            generator: 自定义生成元
        """
        self.p = prime or DH_PRIME  # 使用自定义素数或默认RFC 3526素数
        self.g = generator or DH_GENERATOR  # 使用自定义生成元或默认值2
        # 生成私钥（随机大整数），这是DH安全的核心——私钥只有自己知道
        self.private_key = random.getrandbits(bits)
        # 计算公钥: g^a mod p（a是私钥），这是可以公开发送的
        self.public_key = pow(self.g, self.private_key, self.p)
        self.shared_secret = None  # 共享秘密，协商后计算
        self.session_key = None  # AES会话密钥，从共享秘密派生

    def get_public_key(self):
        """获取本方公钥（可以安全地发送给对方）"""
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        """
        计算共享密钥: (对方公钥)^本方私钥 mod p
        数学原理: 对方公钥 = g^b mod p，本方私钥 = a
        所以 (g^b)^a mod p = g^(ab) mod p
        对方同样计算 (g^a)^b mod p = g^(ab) mod p
        双方得到相同的共享秘密，但窃听者无法从公钥推算私钥（离散对数难题）
        """
        # 验证对方公钥的合法性（必须在1和p之间）
        if other_public_key <= 1 or other_public_key >= self.p:
            raise ValueError("对方公钥无效")
        # 计算共享秘密: 对方公钥^本方私钥 mod p
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        # 将共享秘密转为字节，用于哈希派生密钥
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, 'big'  # 大端序字节表示
        )
        # 使用自实现的SHA-256对共享秘密进行哈希
        from sha256 import sha256
        key_hash = sha256(secret_bytes)  # SHA-256输出32字节
        # 取前16字节作为 AES-128 会话密钥（用于加密数据）
        self.session_key = key_hash[:16]
        # 取后16字节作为 HMAC-SHA256 密钥（用于消息认证）
        self.hmac_key = key_hash[16:32]  # SHA-256输出32字节，16-32正好
        return self.shared_secret

    def get_session_key(self):
        """获取协商出的 AES 会话密钥（16字节，用于AES-128-CBC加密）"""
        return self.session_key

    def get_hmac_key(self):
        """获取协商出的 HMAC 密钥（16字节，用于HMAC-SHA256认证）"""
        return self.hmac_key

    def export_public(self):
        """导出公钥为十六进制字符串（用于网络传输）"""
        return {
            'p': hex(self.p),  # 素数p的十六进制
            'g': self.g,  # 生成元g
            'public_key': hex(self.public_key)  # 公钥的十六进制
        }

    @staticmethod
    def verify_peer_public(peer_public_hex, prime_hex=None):
        """验证对方公钥格式是否合法（1 < pk < p）"""
        try:
            # 将十六进制字符串转为整数
            pk = int(peer_public_hex, 16) if isinstance(peer_public_hex, str) else peer_public_hex
            p = int(prime_hex, 16) if prime_hex else DH_PRIME
            return 1 < pk < p  # 公钥必须在1和p之间
        except:
            return False


if __name__ == '__main__':
    # DH密钥协商测试代码
    print("Diffie-Hellman 密钥协商测试")
    print("=" * 60)

    # Alice 和 Bob 各自生成密钥对
    alice = DHPeer(bits=256)  # Alice生成自己的DH密钥对
    bob = DHPeer(bits=256)  # Bob生成自己的DH密钥对

    print(f"Alice 公钥: {hex(alice.get_public_key())[:40]}...")
    print(f"Bob   公钥: {hex(bob.get_public_key())[:40]}...")

    # 交换公钥，计算共享密钥
    alice.compute_shared_secret(bob.get_public_key())  # Alice用Bob的公钥计算共享秘密
    bob.compute_shared_secret(alice.get_public_key())  # Bob用Alice的公钥计算共享秘密

    print(f"\nAlice 共享密钥: {alice.shared_secret == bob.shared_secret}")  # 验证双方共享秘密相同
    print(f"Alice 会话密钥: {alice.get_session_key().hex()}")  # Alice的AES密钥
    print(f"Bob   会话密钥: {bob.get_session_key().hex()}")  # Bob的AES密钥
    print(f"会话密钥一致: {alice.get_session_key() == bob.get_session_key()}")  # 验证AES密钥相同
    print(f"HMAC密钥一致: {alice.get_hmac_key() == bob.get_hmac_key()}")  # 验证HMAC密钥相同
