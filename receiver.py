"""
接收端主程序 - CLI 版本
流程: Socket接收 → RSA解密密钥 → HMAC验证 → AES解密 → 还原数据
注: CLI简化版不含RSA签名验证，完整版请使用Web界面(app.py)，顺序为: HMAC验证 → AES解密 → RSA签名验证(明文)
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aes import aes_decrypt
from rsa import rsa_decrypt_bytes
from hmac_sha256 import hmac_sha256
from network import unpack_packet, start_receiver


def receiver_main(host='127.0.0.1', port=8888):
    """接收端主流程"""
    print("=" * 70)
    print("  接收端 — 网络安全传输演示")
    print("=" * 70)

    # 读取 RSA 私钥（由发送端生成并保存）
    key_file = 'rsa_private_key.json'
    if not os.path.exists(key_file):
        print(f"\n错误: 未找到 {key_file}，请先运行发送端生成密钥")
        return False

    with open(key_file, 'r') as f:
        key_info = json.load(f)

    priv_key = (key_info['d'], key_info['n'])
    print(f"\n已加载 RSA 私钥 (模数 {key_info['n'].bit_length()} 位)")

    # 定义接收回调
    received = {'result': None}

    def on_receive(packet_data):
        print(f"\n[步骤1] 接收到数据包 ({len(packet_data)} 字节)")

        # 解包
        print("\n[步骤2] 解析数据包...")
        ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value = unpack_packet(packet_data)
        print(f"  密文长度: {len(ciphertext)} 字节")
        print(f"  加密AES密钥长度: {len(encrypted_aes_key)} 字节")
        print(f"  加密HMAC密钥长度: {len(encrypted_hmac_key)} 字节")
        print(f"  IV: {iv.hex() if iv else '无'}")
        print(f"  HMAC值: {hmac_value.hex()}")

        # RSA 解密密钥
        print("\n[步骤3] RSA 解密密钥...")
        aes_key = rsa_decrypt_bytes(encrypted_aes_key, priv_key)
        hmac_key = rsa_decrypt_bytes(encrypted_hmac_key, priv_key)
        print(f"  AES密钥: {aes_key.hex()}")
        print(f"  HMAC密钥: {hmac_key.hex()}")

        # HMAC 验证
        print("\n[步骤4] HMAC-SHA256 验证...")
        computed_hmac = hmac_sha256(hmac_key, ciphertext)
        hmac_valid = (computed_hmac == hmac_value)
        print(f"  计算HMAC: {computed_hmac.hex()}")
        print(f"  接收HMAC: {hmac_value.hex()}")
        print(f"  验证结果: {'通过 ✓' if hmac_valid else '失败 ✗'}")

        if not hmac_valid:
            print("\n✗ HMAC验证失败！数据可能被篡改！")
            received['result'] = False
            return False

        # AES 解密
        print("\n[步骤5] AES-128-CBC 解密...")
        decrypted = aes_decrypt(ciphertext, aes_key, mode='cbc', iv=iv)
        decrypted_text = decrypted.decode('utf-8')
        print(f"  解密后数据:")
        print(f"  {decrypted_text}")

        print(f"\n✓ 接收验证成功！数据完整且未被篡改")
        received['result'] = True
        return True

    # 启动接收服务器
    print(f"\n等待接收数据 (监听 {host}:{port})...")
    thread, event, container = start_receiver(host, port, on_receive, timeout=60)

    # 等待接收完成
    event.wait(timeout=60)

    if container['data'] is not None:
        return container['data']
    else:
        print("\n✗ 接收超时或失败")
        return False


if __name__ == '__main__':
    listen_host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    listen_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    receiver_main(listen_host, listen_port)
