"""
发送端主程序 - CLI 版本
流程: 生成传感器数据 → AES加密 → HMAC认证(Encrypt-then-MAC) → RSA加密密钥 → Socket发送
注: CLI简化版不含RSA签名，完整版请使用Web界面(app.py)，顺序为: RSA签名(明文) → AES加密 → HMAC(密文)
"""
import os
import sys
import json
import time
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aes import aes_encrypt
from rsa import generate_keypair, rsa_encrypt_bytes
from hmac_sha256 import hmac_sha256
from network import pack_packet, send_data


def sender_main(host='127.0.0.1', port=8888):
    """发送端主流程"""
    print("=" * 70)
    print("  发送端 — 网络安全传输演示")
    print("=" * 70)

    # 步骤1: 生成传感器数据
    print("\n[步骤1] 生成传感器数据...")
    sensor_data = []
    for i in range(3):
        sensor = {
            "sensor_id": f"SENSOR_{i + 1:03d}",
            "type": random.choice(["temperature", "humidity", "pressure", "light"]),
            "value": round(random.uniform(10, 90), 2),
            "unit": random.choice(["°C", "%", "hPa", "lux"]),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "location": random.choice(["机房A", "机房B", "仓库C", "办公室D"])
        }
        sensor_data.append(sensor)

    original_text = json.dumps(sensor_data, ensure_ascii=False, indent=2)
    original_bytes = original_text.encode('utf-8')
    print(f"  原始数据 ({len(original_bytes)} 字节):")
    print(f"  {original_text[:100]}...")

    # 步骤2: 生成密钥
    print("\n[步骤2] 生成密钥...")
    aes_key = os.urandom(16)
    hmac_key = os.urandom(32)
    print(f"  AES密钥: {aes_key.hex()}")
    print(f"  HMAC密钥: {hmac_key.hex()}")

    # 步骤3: AES加密
    print("\n[步骤3] AES-128-CBC 加密...")
    iv = os.urandom(16)
    ciphertext, iv_used = aes_encrypt(original_bytes, aes_key, mode='cbc', iv=iv)
    print(f"  IV: {iv_used.hex()}")
    print(f"  密文 ({len(ciphertext)} 字节): {ciphertext.hex()[:64]}...")

    # 步骤4: HMAC认证
    print("\n[步骤4] HMAC-SHA256 消息认证...")
    hmac_value = hmac_sha256(hmac_key, ciphertext)
    print(f"  HMAC值: {hmac_value.hex()}")

    # 步骤5: RSA加密密钥
    print("\n[步骤5] RSA 加密密钥...")
    pub_key, priv_key = generate_keypair(512)
    e, n = pub_key
    d, _ = priv_key

    encrypted_aes_key = rsa_encrypt_bytes(aes_key, pub_key)
    encrypted_hmac_key = rsa_encrypt_bytes(hmac_key, pub_key)
    print(f"  加密后AES密钥 ({len(encrypted_aes_key)} 字节): {encrypted_aes_key.hex()[:40]}...")
    print(f"  加密后HMAC密钥 ({len(encrypted_hmac_key)} 字节): {encrypted_hmac_key.hex()[:40]}...")

    # 步骤6: 封装并发送
    print("\n[步骤6] 封装数据包并通过网络发送...")
    packet = pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=iv_used)
    print(f"  数据包总大小: {len(packet)} 字节")

    # 将私钥保存到文件，供接收端使用
    key_info = {
        'e': e,
        'd': d,
        'n': n
    }
    with open('rsa_private_key.json', 'w') as f:
        json.dump(key_info, f)
    print(f"  RSA私钥已保存到 rsa_private_key.json")

    success = send_data(host, port, packet)
    if success:
        print(f"\n✓ 发送成功！数据已发送至 {host}:{port}")
    else:
        print(f"\n✗ 发送失败！")

    return success


if __name__ == '__main__':
    target_host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    sender_main(target_host, target_port)
