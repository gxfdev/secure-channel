"""
Socket 网络传输模块
实现基于 TCP 的安全数据传输，包含发送端和接收端
自定义协议格式，解决 TCP 粘包问题
"""
import socket
import struct
import threading


# ==================== 协议定义 ====================
# 数据包格式:
# [4字节: 密文长度] [密文数据]
# [4字节: 加密后的AES密钥长度] [加密后的AES密钥数据]
# [4字节: 加密后的HMAC密钥长度] [加密后的HMAC密钥数据]
# [4字节: IV长度] [IV数据]  (CBC模式)
# [32字节: HMAC值]


def pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=None):
    """
    将加密后的各部分数据打包为传输数据包
    """
    packet = b''
    # 密文
    packet += struct.pack('>I', len(ciphertext))
    packet += ciphertext
    # 加密后的AES密钥
    packet += struct.pack('>I', len(encrypted_aes_key))
    packet += encrypted_aes_key
    # 加密后的HMAC密钥
    packet += struct.pack('>I', len(encrypted_hmac_key))
    packet += encrypted_hmac_key
    # IV（CBC模式）
    if iv is not None:
        packet += struct.pack('>I', len(iv))
        packet += iv
    else:
        packet += struct.pack('>I', 0)
    # HMAC值（固定32字节）
    packet += hmac_value
    return packet


def unpack_packet(data):
    """
    解析接收到的数据包
    返回: (ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value)
    """
    offset = 0

    # 读取密文
    ct_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    ciphertext = data[offset:offset + ct_len]
    offset += ct_len

    # 读取加密后的AES密钥
    ek_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    encrypted_aes_key = data[offset:offset + ek_len]
    offset += ek_len

    # 读取加密后的HMAC密钥
    eh_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    encrypted_hmac_key = data[offset:offset + eh_len]
    offset += eh_len

    # 读取IV
    iv_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    iv = data[offset:offset + iv_len] if iv_len > 0 else None
    offset += iv_len

    # 读取HMAC值（最后32字节）
    hmac_value = data[offset:offset + 32]

    return ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value


def recv_exact(sock, n, timeout=10):
    """
    精确接收 n 字节数据
    解决TCP流式传输的半包问题
    """
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已断开")
        data += chunk
    return data


# ==================== 发送端 ====================

def send_data(host, port, packet, timeout=10):
    """
    通过 TCP Socket 发送数据包
    先发送总长度，再发送数据，解决粘包问题
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        # 先发送数据包总长度（4字节）
        sock.sendall(struct.pack('>I', len(packet)))
        # 再发送数据包
        sock.sendall(packet)
        print(f"  [网络] 数据包已发送至 {host}:{port}，总大小: {len(packet)} 字节")
        return True
    except Exception as e:
        print(f"  [网络] 发送失败: {e}")
        return False
    finally:
        sock.close()


# ==================== 接收端 ====================

def start_receiver(host, port, callback, timeout=30):
    """
    启动 TCP 接收服务器
    参数:
        host: 监听地址
        port: 监听端口
        callback: 接收到数据后的回调函数 callback(packet_data) -> result
        timeout: 超时时间（0=持久监听，处理多个连接）
    返回:
        (server_thread, result_event, result_container)
    """
    result_event = threading.Event()
    result_container = {'data': None}
    persistent = (timeout == 0)

    def server_thread():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(timeout if timeout > 0 else 300)
        server_sock.bind((host, port))
        server_sock.listen(5)
        print(f"  [网络] 接收端已启动，监听 {host}:{port}{'（持久模式）' if persistent else ''}")

        while True:
            try:
                conn, addr = server_sock.accept()
                print(f"  [网络] 收到来自 {addr} 的连接")

                # 先读取数据包长度
                length_data = recv_exact(conn, 4, timeout if timeout > 0 else 30)
                total_len = struct.unpack('>I', length_data)[0]
                print(f"  [网络] 接收数据包，大小: {total_len} 字节")

                # 读取完整数据包
                packet_data = recv_exact(conn, total_len, timeout if timeout > 0 else 30)
                print(f"  [网络] 数据包接收完成")

                # 调用回调函数处理数据
                result = callback(packet_data)
                result_container['data'] = result
                result_event.set()

                conn.close()

                if not persistent:
                    break

            except socket.timeout:
                if not persistent:
                    print("  [网络] 接收超时")
                    result_container['data'] = None
                    result_event.set()
                    break
                # 持久模式：继续等待
                continue
            except Exception as e:
                print(f"  [网络] 接收错误: {e}")
                if not persistent:
                    result_container['data'] = None
                    result_event.set()
                    break
                continue

        server_sock.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    return thread, result_event, result_container


if __name__ == '__main__':
    print("网络传输模块测试")
    print("=" * 60)

    import time

    # 测试回环传输
    test_packet = b"This is a test packet for network transmission!"

    def on_receive(data):
        print(f"  [回调] 收到数据: {data[:50]}...")
        return data

    # 启动接收端
    thread, event, container = start_receiver('127.0.0.1', 9999, on_receive)

    # 等待接收端就绪
    time.sleep(0.5)

    # 发送数据
    success = send_data('127.0.0.1', 9999, test_packet)
    print(f"发送结果: {'成功' if success else '失败'}")

    # 等待接收完成
    event.wait(timeout=10)
    if container['data'] is not None:
        print(f"接收结果: {'成功' if container['data'] == test_packet else '失败'}")
    else:
        print("接收结果: 超时或失败")
