"""
Socket 网络传输模块
实现基于 TCP 的安全数据传输，包含发送端和接收端
自定义协议格式，解决 TCP 粘包问题（先发4字节长度，再发数据）
"""
import socket  # 网络通信模块
import struct  # 二进制数据打包/解包
import threading  # 多线程模块，接收端在独立线程中运行


# ==================== 协议定义 ====================
# 数据包格式（自定义二进制协议，解决TCP粘包问题）:
# [4字节: 密文长度] [密文数据]
# [4字节: 加密后的AES密钥长度] [加密后的AES密钥数据]
# [4字节: 加密后的HMAC密钥长度] [加密后的HMAC密钥数据]
# [4字节: IV长度] [IV数据]  (CBC模式，0表示无IV)
# [32字节: HMAC值]


def pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=None):
    """
    将加密后的各部分数据打包为传输数据包
    参数:
        ciphertext: AES加密后的密文
        encrypted_aes_key: RSA加密后的AES密钥
        encrypted_hmac_key: RSA加密后的HMAC密钥
        hmac_value: HMAC-SHA256认证码（32字节）
        iv: AES-CBC的初始化向量（16字节，可选）
    """
    packet = b''  # 初始化空字节串
    # 打包密文：先写4字节长度（大端序无符号整数），再写密文数据
    packet += struct.pack('>I', len(ciphertext))  # '>I' = 大端序4字节无符号整数
    packet += ciphertext
    # 打包加密后的AES密钥
    packet += struct.pack('>I', len(encrypted_aes_key))
    packet += encrypted_aes_key
    # 打包加密后的HMAC密钥
    packet += struct.pack('>I', len(encrypted_hmac_key))
    packet += encrypted_hmac_key
    # 打包IV（CBC模式）
    if iv is not None:  # 如果有IV
        packet += struct.pack('>I', len(iv))  # 写IV长度
        packet += iv  # 写IV数据
    else:  # 没有IV（ECB模式）
        packet += struct.pack('>I', 0)  # 长度写0
    # 打包HMAC值（固定32字节）
    packet += hmac_value
    return packet  # 返回完整的二进制数据包


def unpack_packet(data):
    """
    解析接收到的数据包
    参数: data - 完整的二进制数据包
    返回: (ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value)
    """
    offset = 0  # 当前读取位置

    # 读取密文
    ct_len = struct.unpack('>I', data[offset:offset + 4])[0]  # 读取4字节长度
    offset += 4  # 移动偏移量
    ciphertext = data[offset:offset + ct_len]  # 读取密文数据
    offset += ct_len

    # 读取加密后的AES密钥
    ek_len = struct.unpack('>I', data[offset:offset + 4])[0]  # 读取长度
    offset += 4
    encrypted_aes_key = data[offset:offset + ek_len]  # 读取加密的AES密钥
    offset += ek_len

    # 读取加密后的HMAC密钥
    eh_len = struct.unpack('>I', data[offset:offset + 4])[0]  # 读取长度
    offset += 4
    encrypted_hmac_key = data[offset:offset + eh_len]  # 读取加密的HMAC密钥
    offset += eh_len

    # 读取IV
    iv_len = struct.unpack('>I', data[offset:offset + 4])[0]  # 读取IV长度
    offset += 4
    iv = data[offset:offset + iv_len] if iv_len > 0 else None  # 长度>0才读取，否则为None
    offset += iv_len

    # 读取HMAC值（最后32字节）
    hmac_value = data[offset:offset + 32]

    return ciphertext, encrypted_aes_key, encrypted_hmac_key, iv, hmac_value


def recv_exact(sock, n, timeout=10):
    """
    精确接收 n 字节数据
    解决TCP流式传输的半包问题（一次recv可能收不到全部数据）
    循环接收直到凑够n字节
    """
    sock.settimeout(timeout)  # 设置超时时间
    data = b''  # 已接收的数据
    while len(data) < n:  # 循环直到收够n字节
        chunk = sock.recv(n - len(data))  # 接收剩余需要的字节数
        if not chunk:  # 如果recv返回空，说明连接已断开
            raise ConnectionError("连接已断开")
        data += chunk  # 追加接收到的数据
    return data


# ==================== 发送端 ====================

def send_data(host, port, packet, timeout=10):
    """
    通过 TCP Socket 发送数据包
    先发送总长度（4字节），再发送数据，解决粘包问题
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP Socket
    sock.settimeout(timeout)  # 设置超时时间
    try:
        sock.connect((host, port))  # 连接接收端
        # 先发送数据包总长度（4字节大端序整数）
        sock.sendall(struct.pack('>I', len(packet)))
        # 再发送完整数据包
        sock.sendall(packet)
        print(f"  [网络] 数据包已发送至 {host}:{port}，总大小: {len(packet)} 字节")
        return True  # 发送成功
    except Exception as e:
        print(f"  [网络] 发送失败: {e}")
        return False  # 发送失败
    finally:
        sock.close()  # 无论成功失败都关闭连接


# ==================== 接收端 ====================

def start_receiver(host, port, callback, timeout=30):
    """
    启动 TCP 接收服务器（在独立线程中运行）
    参数:
        host: 监听地址（通常为'0.0.0.0'或'127.0.0.1'）
        port: 监听端口
        callback: 接收到数据后的回调函数 callback(packet_data) -> result
        timeout: 超时时间（0=持久监听，处理多个连接）
    返回:
        (server_thread, result_event, result_container)
    """
    result_event = threading.Event()  # 事件对象，用于通知主线程接收完成
    result_container = {'data': None}  # 存储接收结果的容器
    persistent = (timeout == 0)  # 是否持久模式（timeout=0时持久监听）

    def server_thread():
        """接收服务器线程函数"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP Socket
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 允许端口复用
        server_sock.settimeout(timeout if timeout > 0 else 300)  # 设置超时
        server_sock.bind((host, port))  # 绑定地址和端口
        server_sock.listen(5)  # 开始监听，backlog=5
        print(f"  [网络] 接收端已启动，监听 {host}:{port}{'（持久模式）' if persistent else ''}")

        while True:  # 主循环
            try:
                conn, addr = server_sock.accept()  # 等待客户端连接
                print(f"  [网络] 收到来自 {addr} 的连接")

                # 先读取数据包长度（4字节）
                length_data = recv_exact(conn, 4, timeout if timeout > 0 else 30)
                total_len = struct.unpack('>I', length_data)[0]  # 解析总长度
                print(f"  [网络] 接收数据包，大小: {total_len} 字节")

                # 读取完整数据包
                packet_data = recv_exact(conn, total_len, timeout if timeout > 0 else 30)
                print(f"  [网络] 数据包接收完成")

                # 调用回调函数处理数据
                result = callback(packet_data)
                result_container['data'] = result  # 存储结果
                result_event.set()  # 通知主线程

                conn.close()  # 关闭连接

                if not persistent:  # 非持久模式，处理完一个连接后退出
                    break

            except socket.timeout:  # 超时
                if not persistent:  # 非持久模式
                    print("  [网络] 接收超时")
                    result_container['data'] = None
                    result_event.set()
                    break
                continue  # 持久模式：继续等待
            except Exception as e:  # 其他异常
                print(f"  [网络] 接收错误: {e}")
                if not persistent:
                    result_container['data'] = None
                    result_event.set()
                    break
                continue  # 持久模式：继续等待

        server_sock.close()  # 关闭服务器Socket

    thread = threading.Thread(target=server_thread, daemon=True)  # 创建守护线程
    thread.start()  # 启动线程

    return thread, result_event, result_container  # 返回线程、事件和结果容器


if __name__ == '__main__':
    # 网络传输模块回环测试
    print("网络传输模块测试")
    print("=" * 60)

    import time

    test_packet = b"This is a test packet for network transmission!"  # 测试数据

    def on_receive(data):
        """接收回调函数"""
        print(f"  [回调] 收到数据: {data[:50]}...")
        return data

    # 启动接收端
    thread, event, container = start_receiver('127.0.0.1', 9999, on_receive)
    time.sleep(0.5)  # 等待接收端就绪

    # 发送数据
    success = send_data('127.0.0.1', 9999, test_packet)
    print(f"发送结果: {'成功' if success else '失败'}")

    # 等待接收完成
    event.wait(timeout=10)
    if container['data'] is not None:
        print(f"接收结果: {'成功' if container['data'] == test_packet else '失败'}")
    else:
        print("接收结果: 超时或失败")
