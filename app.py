"""
Flask Web 应用 - 网络安全传输演示系统
完整流程: TCP连接 → DH密钥协商(带签名) → 数据加密传输 → 验证解密

环境变量:
  MODE: sender / receiver（默认 sender）
  RECEIVER_HOST: 接收端IP
  RECEIVER_PORT: 数据传输端口（默认 9999）
  LISTEN_PORT: 监听端口（默认 9999）
  RSA_BITS: RSA密钥位数（默认 512）
  DATA_DIR: 数据包存储目录（默认 ./captured_data）
  FLASK_HOST: Flask监听地址（默认 0.0.0.0）
  FLASK_PORT: Flask监听端口（默认 5000）
"""
import os
import sys
import json
import time
import socket
import struct
import threading
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request

from aes import aes_encrypt, aes_decrypt
from rsa import generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_sign, rsa_verify, save_keypair
from sha256 import sha256
from hmac_sha256 import hmac_sha256
from dh import DHPeer
from capture import capture_packets, packets_to_json, get_network_info, HAS_SCAPY

app = Flask(__name__)

# 配置
MODE = os.environ.get('MODE', 'sender') or 'sender'
RECEIVER_HOST = os.environ.get('RECEIVER_HOST', '127.0.0.1') or '127.0.0.1'
RECEIVER_PORT = int(os.environ.get('RECEIVER_PORT', '9999') or '9999')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT', '9999') or '9999')
RSA_BITS = int(os.environ.get('RSA_BITS', '512') or '512')
DATA_DIR = os.environ.get('DATA_DIR', './captured_data') or './captured_data'
FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0') or '0.0.0.0'
FLASK_PORT = int(os.environ.get('FLASK_PORT', '5000') or '5000')

# 创建数据存储目录
os.makedirs(DATA_DIR, exist_ok=True)

# 全局状态
_rsa_keys = None
_rsa_lock = threading.Lock()
_dh_peer = None
_connection_state = {
    'status': 'disconnected',  # disconnected / connecting / negotiating / connected
    'peer_ip': None,
    'peer_port': None,
    'tcp_handshake': [],
    'dh_exchange': [],
    'session_key': None,
    'hmac_key': None,
    'peer_public_key': None,
    'peer_verified': False,
}
_received_data = []
_key_files = {'pub': None, 'priv': None}


def get_rsa_keys():
    """获取或生成 RSA 密钥对，并保存到文件"""
    global _rsa_keys, _key_files
    with _rsa_lock:
        if _rsa_keys is None:
            _rsa_keys = generate_keypair(RSA_BITS)
            pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                                prefix=os.path.join(DATA_DIR, 'rsa_key'))
            _key_files['pub'] = os.path.abspath(pub_path)
            _key_files['priv'] = os.path.abspath(priv_path)
    return _rsa_keys


# ==================== 页面路由 ====================

@app.route('/')
def index():
    return render_template('index.html')


# ==================== 信息 API ====================

@app.route('/api/info')
def get_info():
    net_info = get_network_info()
    pub_key, _ = get_rsa_keys()
    e, n = pub_key
    return jsonify({
        'mode': MODE,
        'hostname': net_info['hostname'],
        'ip': net_info.get('ip_address', '127.0.0.1'),
        'interfaces': net_info.get('interfaces', []),
        'receiver_host': RECEIVER_HOST,
        'receiver_port': RECEIVER_PORT,
        'listen_port': LISTEN_PORT,
        'scapy_available': HAS_SCAPY,
        'rsa_bits': RSA_BITS,
        'data_dir': os.path.abspath(DATA_DIR),
        'public_key_file': _key_files.get('pub', ''),
        'private_key_file': _key_files.get('priv', ''),
        'public_key_e': e,
        'public_key_n_hex': hex(n)[:40] + '...',
        'connection': _connection_state,
        'received_count': len(_received_data),
    })


# ==================== 连接建立 API ====================

@app.route('/api/connect', methods=['POST'])
def api_connect():
    """
    发送端: 建立与接收端的 TCP 连接 + DH 密钥协商
    流程:
    1. TCP 三次握手
    2. 交换 DH 公钥（带 RSA 签名）
    3. 验证对方签名
    4. 计算共享会话密钥
    """
    global _dh_peer, _connection_state

    try:
        data = request.get_json() or {}
        target_host = data.get('host', RECEIVER_HOST)
        target_port = int(data.get('port', RECEIVER_PORT))

        _connection_state['status'] = 'connecting'
        _connection_state['peer_ip'] = target_host
        _connection_state['peer_port'] = target_port
        _connection_state['tcp_handshake'] = []
        _connection_state['dh_exchange'] = []

        result = {'steps': [], 'success': False}

        # ===== 步骤1: TCP 三次握手 =====
        local_ip = socket.gethostbyname(socket.gethostname())
        local_port = random.randint(40000, 60000)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # 记录握手过程
        handshake_info = [
            {'step': 1, 'dir': '→', 'from': f'{local_ip}:{local_port}', 'to': f'{target_host}:{target_port}',
             'flag': 'SYN', 'desc': '发送 SYN 包，请求建立连接'},
            {'step': 2, 'dir': '←', 'from': f'{target_host}:{target_port}', 'to': f'{local_ip}:{local_port}',
             'flag': 'SYN+ACK', 'desc': '接收 SYN+ACK 包，对方确认连接'},
            {'step': 3, 'dir': '→', 'from': f'{local_ip}:{local_port}', 'to': f'{target_host}:{target_port}',
             'flag': 'ACK', 'desc': '发送 ACK 包，连接建立完成'},
        ]
        _connection_state['tcp_handshake'] = handshake_info

        result['steps'].append({
            'id': 1, 'title': 'TCP 三次握手',
            'description': '与接收端建立可靠的 TCP 连接',
            'data': {
                '本地地址': f'{local_ip}:{local_port}',
                '目标地址': f'{target_host}:{target_port}',
                '握手过程': handshake_info
            }
        })

        # 实际建立 TCP 连接
        try:
            sock.connect((target_host, target_port))
        except Exception as e:
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP连接失败: {e}', 'steps': result['steps']})

        # ===== 步骤2: 请求对方公钥 =====
        _connection_state['status'] = 'negotiating'

        # 发送协商请求（包含本方监听端口，用于双向通信）
        negotiate_req = json.dumps({
            'type': 'negotiate_request',
            'listen_port': LISTEN_PORT
        }).encode()
        sock.sendall(struct.pack('>I', len(negotiate_req)) + negotiate_req)

        # 接收对方响应（公钥 + DH公钥 + 签名）
        resp_len = struct.unpack('>I', _recv_exact(sock, 4))[0]
        resp_data = _recv_exact(sock, resp_len)
        peer_info = json.loads(resp_data.decode())

        peer_rsa_e = peer_info['rsa_e']
        peer_rsa_n = peer_info['rsa_n']
        peer_dh_public = int(peer_info['dh_public'], 16)
        peer_dh_signature = bytes.fromhex(peer_info['dh_signature'])
        peer_rsa_pub = (peer_rsa_e, peer_rsa_n)

        # 保存对方的监听端口（用于反向发送数据）
        peer_listen_port = peer_info.get('listen_port', LISTEN_PORT)
        _connection_state['peer_listen_port'] = peer_listen_port
        _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}

        # ===== 步骤3: 生成 DH 密钥对 =====
        _dh_peer = DHPeer(bits=256)
        my_dh_public = _dh_peer.get_public_key()

        # 用本方私钥对 DH 公钥签名（不可否认性）
        my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
        my_signature = rsa_sign(my_dh_public_bytes, get_rsa_keys()[1])

        # 发送本方信息（包含监听端口，用于双向通信）
        my_info = json.dumps({
            'type': 'negotiate_response',
            'rsa_e': get_rsa_keys()[0][0],
            'rsa_n': get_rsa_keys()[0][1],
            'dh_public': hex(my_dh_public),
            'dh_signature': my_signature.hex(),
            'listen_port': LISTEN_PORT
        }).encode()
        sock.sendall(struct.pack('>I', len(my_info)) + my_info)

        # ===== 步骤4: 验证对方签名 =====
        peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')
        peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)

        _connection_state['peer_verified'] = peer_verified

        result['steps'].append({
            'id': 2, 'title': 'DH 密钥协商 + 数字签名',
            'description': '交换 DH 公钥，用 RSA 私钥签名保证真实性，验证对方签名',
            'data': {
                '本方DH公钥': hex(my_dh_public)[:40] + '...',
                '对方DH公钥': hex(peer_dh_public)[:40] + '...',
                '本方签名(私钥签名)': my_signature.hex()[:40] + '...',
                '对方签名验证': '通过 ✓' if peer_verified else '失败 ✗',
                '对方RSA公钥e': peer_rsa_e,
                '对方RSA位数': f'{peer_rsa_n.bit_length()} 位',
                '签名算法': 'RSA-SHA256 (先SHA256哈希，再RSA私钥签名)',
                '安全性': '私钥签名保证不可否认性和真实性'
            }
        })

        if not peer_verified:
            sock.close()
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': '对方签名验证失败！可能遭受中间人攻击', 'steps': result['steps']})

        # ===== 步骤5: 计算共享会话密钥 =====
        _dh_peer.compute_shared_secret(peer_dh_public)
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        _connection_state['session_key'] = session_key.hex()
        _connection_state['hmac_key'] = hmac_key.hex()
        _connection_state['status'] = 'connected'

        # 保存连接会话
        sock.close()  # 协商完成，关闭协商连接，后续数据传输用新连接

        result['steps'].append({
            'id': 3, 'title': '协商完成 - 会话密钥生成',
            'description': '双方独立计算出相同的共享密钥，派生 AES 会话密钥和 HMAC 密钥',
            'data': {
                '共享密钥协商': 'DH: g^(ab) mod p',
                'AES会话密钥': session_key.hex(),
                'HMAC密钥': hmac_key.hex(),
                '密钥派生': 'SHA-256(共享密钥) → 前16字节=AES密钥, 后16字节=HMAC密钥',
                'DH素数群': 'RFC 3526 2048-bit MODP Group'
            }
        })

        result['success'] = True
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        _connection_state['status'] = 'disconnected'
        return jsonify({'success': False, 'error': str(e)})


# ==================== 接收端协商服务 ====================

_negotiate_server_running = False


def start_negotiate_server():
    """启动接收端的协商服务器，等待发送端连接"""
    global _negotiate_server_running, _dh_peer, _connection_state

    if _negotiate_server_running:
        return

    def server_thread():
        global _dh_peer, _connection_state
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(300)
        server_sock.bind(('0.0.0.0', LISTEN_PORT))
        server_sock.listen(5)
        print(f"  [协商服务器] 监听 0.0.0.0:{LISTEN_PORT}")
        _negotiate_server_running = True

        while True:
            try:
                conn, addr = server_sock.accept()
                print(f"  [协商服务器] 收到来自 {addr} 的连接")

                _connection_state['peer_ip'] = addr[0]
                _connection_state['peer_port'] = addr[1]
                _connection_state['status'] = 'negotiating'

                # 读取协商请求
                req_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                req_data = _recv_exact(conn, req_len)
                req = json.loads(req_data.decode())

                # 保存对方的监听端口
                peer_listen_port = req.get('listen_port', LISTEN_PORT)

                if req.get('type') == 'negotiate_request':
                    # 生成 DH 密钥对
                    _dh_peer = DHPeer(bits=256)
                    my_dh_public = _dh_peer.get_public_key()

                    # 用私钥签名 DH 公钥
                    my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
                    my_signature = rsa_sign(my_dh_public_bytes, get_rsa_keys()[1])

                    # 发送本方公钥 + DH公钥 + 签名 + 监听端口
                    pub_key = get_rsa_keys()[0]
                    response = json.dumps({
                        'type': 'negotiate_response',
                        'rsa_e': pub_key[0],
                        'rsa_n': pub_key[1],
                        'dh_public': hex(my_dh_public),
                        'dh_signature': my_signature.hex(),
                        'listen_port': LISTEN_PORT
                    }).encode()
                    conn.sendall(struct.pack('>I', len(response)) + response)

                    # 接收对方信息
                    resp_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                    resp_data = _recv_exact(conn, resp_len)
                    peer_info = json.loads(resp_data.decode())

                    peer_rsa_e = peer_info['rsa_e']
                    peer_rsa_n = peer_info['rsa_n']
                    peer_dh_public = int(peer_info['dh_public'], 16)
                    peer_dh_signature = bytes.fromhex(peer_info['dh_signature'])
                    peer_rsa_pub = (peer_rsa_e, peer_rsa_n)

                    # 验证对方签名
                    peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')
                    peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)

                    _connection_state['peer_verified'] = peer_verified
                    _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}
                    _connection_state['peer_listen_port'] = peer_info.get('listen_port', peer_listen_port)

                    if peer_verified:
                        # 计算共享密钥
                        _dh_peer.compute_shared_secret(peer_dh_public)
                        _connection_state['session_key'] = _dh_peer.get_session_key().hex()
                        _connection_state['hmac_key'] = _dh_peer.get_hmac_key().hex()
                        _connection_state['status'] = 'connected'
                        print(f"  [协商服务器] 密钥协商完成，会话密钥已建立")
                    else:
                        _connection_state['status'] = 'disconnected'
                        print(f"  [协商服务器] 对方签名验证失败！")

                elif req.get('type') == 'data_transfer':
                    # 数据传输
                    if _dh_peer and _dh_peer.get_session_key():
                        _handle_data_transfer(conn, req)

                conn.close()

            except socket.timeout:
                continue
            except Exception as e:
                print(f"  [协商服务器] 错误: {e}")
                continue

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()


def _handle_data_transfer(conn, req):
    """处理数据传输"""
    global _received_data
    try:
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        # 读取加密数据
        data_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
        encrypted_packet = _recv_exact(conn, data_len)

        # 解析数据包
        from network import unpack_packet
        ct, _, _, recv_iv, recv_hmac = unpack_packet(encrypted_packet)

        # HMAC 验证（完整性）
        computed_hmac = hmac_sha256(hmac_key, ct)
        hmac_valid = (computed_hmac == recv_hmac)

        if hmac_valid:
            decrypted = aes_decrypt(ct, session_key, mode='cbc', iv=recv_iv)
            decrypted_text = decrypted.decode('utf-8')

            # 保存到文件
            filename = f"received_{int(time.time())}.json"
            filepath = os.path.join(DATA_DIR, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(decrypted_text)

            record = {
                'time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'hmac_valid': True,
                'decrypted_data': decrypted_text,
                'saved_to': os.path.abspath(filepath),
                'ciphertext_hex': ct.hex()[:128] + '...',
                'session_key_hex': session_key.hex(),
                'hmac_key_hex': hmac_key.hex(),
                'iv_hex': recv_iv.hex() if recv_iv else '',
                'hmac_value': recv_hmac.hex()
            }
        else:
            record = {
                'time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'hmac_valid': False,
                'error': 'HMAC验证失败，数据可能被篡改！'
            }

        _received_data.append(record)

    except Exception as e:
        _received_data.append({
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'hmac_valid': False,
            'error': str(e)
        })


def _recv_exact(sock, n, timeout=15):
    """精确接收 n 字节"""
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已断开")
        data += chunk
    return data


# ==================== 抓包 API ====================

@app.route('/api/capture', methods=['POST'])
def api_capture():
    """抓取网络数据包（详细版，包含抓包过程日志）"""
    try:
        count = request.json.get('count', 10) if request.is_json else 10
        timeout = request.json.get('timeout', 15) if request.is_json else 15

        packets, capture_log = capture_packets(count=count, timeout=timeout)

        if not packets:
            return jsonify({'success': False, 'error': '未抓取到任何数据包', 'capture_log': capture_log})

        # 保存到文件
        json_data = packets_to_json(packets)
        filename = f"capture_{int(time.time())}.json"
        filepath = os.path.join(DATA_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(json_data)

        return jsonify({
            'success': True,
            'packets': packets,
            'count': len(packets),
            'json_data': json_data,
            'saved_to': os.path.abspath(filepath),
            'capture_log': capture_log
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==================== 加密发送 API ====================

@app.route('/api/send', methods=['POST'])
def api_send():
    """发送端: 用协商好的会话密钥加密数据并发送"""
    try:
        if not _dh_peer or not _dh_peer.get_session_key():
            return jsonify({'success': False, 'error': '尚未建立连接，请先连接接收端进行密钥协商'})

        data = request.get_json()
        original_text = data.get('data', '')
        target_host = _connection_state.get('peer_ip') or data.get('receiver_host', RECEIVER_HOST)
        # 数据传输使用对方的固定监听端口（支持双向通信）
        target_port = _connection_state.get('peer_listen_port', LISTEN_PORT)

        if not original_text:
            return jsonify({'success': False, 'error': '没有可发送的数据'})

        result = {'steps': [], 'success': False}
        original_bytes = original_text.encode('utf-8')
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        # 步骤1: 原始数据
        result['steps'].append({
            'id': 1, 'title': '原始数据（抓取的网络数据包）',
            'description': '从网络中采集到的真实数据包',
            'data': {
                '数据长度': f'{len(original_bytes)} 字节',
                '数据预览': original_text[:300] + ('...' if len(original_text) > 300 else ''),
                '十六进制预览': original_bytes.hex()[:128] + '...'
            }
        })

        # 步骤2: AES 加密（使用协商出的会话密钥）
        iv = os.urandom(16)
        ciphertext, iv_used = aes_encrypt(original_bytes, session_key, mode='cbc', iv=iv)
        result['steps'].append({
            'id': 2, 'title': 'AES-128-CBC 加密（DH协商密钥）',
            'description': '使用 DH 密钥协商得出的会话密钥加密数据',
            'data': {
                '会话密钥来源': 'DH密钥协商',
                'AES密钥': session_key.hex(),
                'IV': iv_used.hex(),
                '密文': ciphertext.hex()[:128] + '...',
                '密文长度': f'{len(ciphertext)} 字节'
            }
        })

        # 步骤3: HMAC 认证（完整性）
        hmac_value = hmac_sha256(hmac_key, ciphertext)
        result['steps'].append({
            'id': 3, 'title': 'HMAC-SHA256 消息认证（完整性）',
            'description': '对密文计算消息认证码，保证数据完整性',
            'data': {
                'HMAC密钥来源': 'DH密钥协商派生',
                'HMAC密钥': hmac_key.hex(),
                'HMAC值': hmac_value.hex()
            }
        })

        # 步骤4: RSA 签名（不可否认性）
        signature = rsa_sign(ciphertext, get_rsa_keys()[1])
        result['steps'].append({
            'id': 4, 'title': 'RSA 数字签名（不可否认性）',
            'description': '用发送端私钥对密文签名，接收端可用公钥验证，保证不可否认性',
            'data': {
                '签名算法': 'RSA-SHA256',
                '签名流程': 'SHA-256(密文) → RSA私钥加密 → 签名',
                '签名值': signature.hex()[:64] + '...',
                '安全性': '私钥签名保证不可否认性和真实性'
            }
        })

        # 步骤5: 封装并发送
        from network import pack_packet
        packet = pack_packet(ciphertext, b'', b'', hmac_value, iv=iv_used)

        # 建立新的 TCP 连接发送数据
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((target_host, target_port))
            # 发送数据传输请求
            req = json.dumps({'type': 'data_transfer'}).encode()
            sock.sendall(struct.pack('>I', len(req)) + req)
            # 发送加密数据包
            sock.sendall(struct.pack('>I', len(packet)) + packet)
            # 发送签名
            sock.sendall(struct.pack('>I', len(signature)) + signature)
            send_success = True
        except Exception as e:
            send_success = False
            result['error'] = f'发送失败: {e}'
        finally:
            sock.close()

        result['steps'].append({
            'id': 5, 'title': '网络传输',
            'description': '通过 TCP Socket 发送加密数据包和数字签名到接收端',
            'data': {
                '目标': f'{target_host}:{target_port}',
                '数据包大小': f'{len(packet)} 字节',
                '签名大小': f'{len(signature)} 字节',
                '发送状态': '成功' if send_success else '失败',
                '传输内容': '加密数据 + HMAC + 数字签名'
            }
        })

        result['success'] = send_success
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})


# ==================== 接收端 API ====================

@app.route('/api/received_data')
def get_received_data():
    return jsonify({'count': len(_received_data), 'data': _received_data})


@app.route('/api/connection_status')
def connection_status():
    return jsonify(_connection_state)


# ==================== 算法测试 API ====================

@app.route('/api/test_algo', methods=['POST'])
def test_algorithms():
    results = {}
    try:
        key = os.urandom(16); iv = os.urandom(16)
        pt = b"Test AES"
        ct, iv2 = aes_encrypt(pt, key, mode='cbc', iv=iv)
        results['AES-128-CBC'] = 'PASS' if aes_decrypt(ct, key, mode='cbc', iv=iv2) == pt else 'FAIL'
    except Exception as e:
        results['AES-128-CBC'] = f'ERROR: {e}'

    try:
        pub, priv = generate_keypair(RSA_BITS)
        td = b"RSA_TEST"
        enc = rsa_encrypt_bytes(td, pub)
        dec = rsa_decrypt_bytes(enc, priv)
        sig = rsa_sign(td, priv)
        verified = rsa_verify(td, sig, pub)
        results['RSA+签名'] = 'PASS' if dec == td and verified else 'FAIL'
    except Exception as e:
        results['RSA+签名'] = f'ERROR: {e}'

    try:
        h = sha256(b"abc").hex()
        results['SHA-256'] = 'PASS' if h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" else 'FAIL'
    except Exception as e:
        results['SHA-256'] = f'ERROR: {e}'

    try:
        a = DHPeer(); b = DHPeer()
        a.compute_shared_secret(b.get_public_key())
        b.compute_shared_secret(a.get_public_key())
        results['DH协商'] = 'PASS' if a.get_session_key() == b.get_session_key() else 'FAIL'
    except Exception as e:
        results['DH协商'] = f'ERROR: {e}'

    try:
        h = hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex()
        results['HMAC-SHA256'] = 'PASS' if h == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" else 'FAIL'
    except Exception as e:
        results['HMAC-SHA256'] = f'ERROR: {e}'

    return jsonify(results)


# ==================== 启动 ====================

if __name__ == '__main__':
    print("=" * 60)
    print(f"  网络安全传输演示系统 — {'发送端' if MODE == 'sender' else '接收端'}模式")
    print(f"  MODE={MODE}")
    print(f"  数据存储目录: {os.path.abspath(DATA_DIR)}")
    print("=" * 60)

    print("\n生成 RSA 密钥对...")
    get_rsa_keys()
    print(f"RSA 密钥对就绪！")
    print(f"  公钥文件: {_key_files['pub']}")
    print(f"  私钥文件: {_key_files['priv']}")

    # 启动协商服务器
    print(f"\n启动协商服务器（端口 {LISTEN_PORT}）...")
    start_negotiate_server()

    print(f"\nWeb 界面: http://{FLASK_HOST}:{FLASK_PORT}\n")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
