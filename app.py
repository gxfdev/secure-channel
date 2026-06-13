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
_negotiate_server_status = {'running': False, 'port': None, 'error': None}


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
    pub_key, priv_key = get_rsa_keys()
    e, n = pub_key
    d, _ = priv_key

    # 构建密钥信息
    key_info = {
        'rsa': {
            'public_key': {
                'e': e,
                'n': hex(n),
                'n_bits': n.bit_length(),
            },
            'private_key': {
                'd': hex(d),
                'd_bits': d.bit_length(),
            },
            'public_key_file': _key_files.get('pub', ''),
            'private_key_file': _key_files.get('priv', ''),
        },
        'dh': None,
        'session': None,
    }

    # 如果已建立连接，显示DH和会话密钥
    if _dh_peer:
        key_info['dh'] = {
            'private_key': hex(_dh_peer.private_key),
            'public_key': hex(_dh_peer.public_key),
            'shared_secret': hex(_dh_peer.shared_secret) if _dh_peer.shared_secret else None,
        }
    if _connection_state.get('session_key'):
        key_info['session'] = {
            'aes_key': _connection_state['session_key'],
            'hmac_key': _connection_state['hmac_key'],
        }

    return jsonify({
        'mode': MODE,
        'hostname': net_info['hostname'],
        'ip': net_info.get('ip_address', '127.0.0.1'),
        'interfaces': net_info.get('interfaces', []),
        'scapy_interfaces': net_info.get('scapy_interfaces', []),
        'receiver_host': RECEIVER_HOST,
        'receiver_port': RECEIVER_PORT,
        'listen_port': LISTEN_PORT,
        'scapy_available': HAS_SCAPY,
        'rsa_bits': RSA_BITS,
        'data_dir': os.path.abspath(DATA_DIR),
        'public_key_e': e,
        'public_key_n_hex': hex(n),
        'key_info': key_info,
        'connection': _connection_state,
        'received_count': len(_received_data),
        'negotiate_server': _negotiate_server_status,
    })


@app.route('/api/health')
def health_check():
    """健康检查：协商服务器是否在监听"""
    import subprocess
    result = {
        'negotiate_server': _negotiate_server_status,
        'listen_port': LISTEN_PORT,
        'port_listening': False,
        'scapy_available': HAS_SCAPY,
        'network_debug': {},
    }
    # 检查端口是否在监听
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(1)
        test_sock.connect(('127.0.0.1', LISTEN_PORT))
        test_sock.close()
        result['port_listening'] = True
    except:
        result['port_listening'] = False

    # 网络诊断信息
    try:
        result['network_debug']['hostname'] = socket.gethostname()
        # UDP trick获取真实IP
        outbound_ip = '127.0.0.1'
        for target in ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1']:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((target, 80))
                outbound_ip = s.getsockname()[0]
                s.close()
                break
            except:
                try: s.close()
                except: pass
        result['network_debug']['ip'] = outbound_ip
        result['network_debug']['outbound_ip'] = outbound_ip
    except:
        pass

    # scapy 接口信息
    if HAS_SCAPY:
        try:
            from scapy.all import get_if_list, get_if_addr, conf
            ifaces = []
            for iface in get_if_list():
                try:
                    ip = get_if_addr(str(iface))
                    ifaces.append({'name': str(iface), 'ip': ip})
                except:
                    ifaces.append({'name': str(iface), 'ip': 'N/A'})
            result['network_debug']['scapy_ifaces'] = ifaces
            result['network_debug']['scapy_default_iface'] = str(conf.iface)
        except Exception as e:
            result['network_debug']['scapy_error'] = str(e)

    return jsonify(result)


@app.route('/api/test_tcp', methods=['POST'])
def test_tcp():
    """测试与目标主机的 TCP 连通性"""
    try:
        data = request.get_json() or {}
        host = data.get('host', RECEIVER_HOST)
        port = int(data.get('port', LISTEN_PORT))
        results = []

        # 1. DNS 解析测试（如果是IP地址则跳过）
        import re
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', host)
        if is_ip:
            results.append({'step': 'DNS解析', 'ok': True, 'detail': f'{host} 是IP地址，无需DNS解析'})
        else:
            try:
                resolved_ip = socket.gethostbyname(host)
                results.append({'step': 'DNS解析', 'ok': True, 'detail': f'{host} → {resolved_ip}'})
            except Exception as e:
                results.append({'step': 'DNS解析', 'ok': False, 'detail': str(e)})
                return jsonify({'success': False, 'results': results, 'error': 'DNS解析失败'})

        # 2. ICMP ping 测试（尝试连接）
        start = time.time()
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            test_sock.connect((host, port))
            latency = round((time.time() - start) * 1000, 1)
            test_sock.close()
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': True, 'detail': f'成功，延迟 {latency}ms'})
        except socket.timeout:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': '连接超时（3秒），目标端口未开放或被防火墙阻止'})
            return jsonify({'success': False, 'results': results, 'error': 'TCP连接超时'})
        except ConnectionRefusedError:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': '连接被拒绝，目标端口未监听或服务未启动'})
            return jsonify({'success': False, 'results': results, 'error': '连接被拒绝'})
        except Exception as e:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': str(e)})
            return jsonify({'success': False, 'results': results, 'error': str(e)})

        # 3. 发送协商协议测试（完整 ping-pong）
        try:
            test_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock2.settimeout(5)
            test_sock2.connect((host, port))
            # 发送 ping
            ping_msg = json.dumps({'type': 'ping'}).encode()
            test_sock2.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
            # 读取 pong 响应
            pong_len = struct.unpack('>I', _recv_exact(test_sock2, 4))[0]
            pong_data = _recv_exact(test_sock2, pong_len)
            pong = json.loads(pong_data.decode())
            test_sock2.close()
            if pong.get('type') == 'pong':
                results.append({'step': '协议通信', 'ok': True, 'detail': f"对方模式: {pong.get('mode','?')}, 监听端口: {pong.get('listen_port','?')}"})
            else:
                results.append({'step': '协议通信', 'ok': False, 'detail': f"收到异常响应: {pong}"})
        except Exception as e:
            results.append({'step': '协议通信', 'ok': False, 'detail': str(e)})

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/set_mode', methods=['POST'])
def set_mode():
    """运行时切换模式（发送端/接收端）"""
    global MODE, _negotiate_server_running, _negotiate_server_status
    data = request.get_json() or {}
    new_mode = data.get('mode', '')
    if new_mode not in ('sender', 'receiver'):
        return jsonify({'success': False, 'error': '模式必须是 sender 或 receiver'})
    if new_mode == MODE:
        return jsonify({'success': True, 'mode': MODE, 'message': f'已经是{("发送端" if MODE=="sender" else "接收端")}模式'})
    MODE = new_mode
    # 如果协商服务器还没启动，启动它
    if not _negotiate_server_running:
        start_negotiate_server()
    mode_label = '发送端' if MODE == 'sender' else '接收端'
    return jsonify({'success': True, 'mode': MODE, 'message': f'已切换为{mode_label}模式'})


# ==================== 连接建立 API ====================

@app.route('/api/connect', methods=['POST'])
def api_connect():
    """
    发送端: 建立与接收端的 TCP 连接 + 完整的密钥交换流程（5步）

    流程设计:
    ┌─────────────────────────────────────────────────────────────┐
    │  步骤1: TCP 三次握手 → 建立可靠连接                         │
    │  步骤2: 交换 RSA 公钥 → 我发我的公钥给你，你发你的公钥给我   │
    │  步骤3: 交换 DH 公钥(带RSA签名) → 签名保证DH公钥真实性       │
    │  步骤4: 验证对方签名 → 用对方RSA公钥验证对方DH公钥签名        │
    │  步骤5: 计算共享会话密钥 → 双方独立算出相同的AES+HMAC密钥     │
    └─────────────────────────────────────────────────────────────┘
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

        # ================================================================
        # 步骤 1: TCP 三次握手
        # ================================================================
        # 获取本机真实IP（不依赖DNS，UDP trick不需要真的发包）
        local_ip = '127.0.0.1'
        for _target in ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1']:
            try:
                _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _s.settimeout(1)
                _s.connect((_target, 80))
                local_ip = _s.getsockname()[0]
                _s.close()
                break
            except:
                try: _s.close()
                except: pass
        local_port = random.randint(40000, 60000)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # 30秒超时，给密钥协商足够时间

        # 生成真实的 TCP 参数（模拟实际握手报文）
        seq1 = random.randint(100000000, 999999999)
        seq2 = random.randint(100000000, 999999999)
        win_size = random.choice([8192, 16384, 32768, 65535])
        mss = 1460

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
            'id': 1,
            'title': '步骤1: TCP 三次握手',
            'status': 'success',
            'description': '与接收端建立可靠的 TCP 连接（三次握手保证双方收发能力正常）',
            'detail': {
                '连接参数': {
                    '发送端(本机)': f'{local_ip}:{local_port}',
                    '接收端(目标)': f'{target_host}:{target_port}',
                    '协议': 'TCP (Transmission Control Protocol)',
                    '窗口大小': str(win_size),
                    'MSS': str(mss)
                },
                '第1次握手 (SYN)': {
                    '方向': f'{local_ip}:{local_port} → {target_host}:{target_port}',
                    '标志位': 'SYN=1',
                    '序列号(seq)': str(seq1),
                    '确认号(ack)': '0 (首次握手无确认号)',
                    '窗口大小': str(win_size),
                    'TCP选项': f'MSS={mss}',
                    '含义': '发送端告诉接收端：我想建立连接，我的初始序列号是'+str(seq1)
                },
                '第2次握手 (SYN+ACK)': {
                    '方向': f'{target_host}:{target_port} → {local_ip}:{local_port}',
                    '标志位': 'SYN=1, ACK=1',
                    '序列号(seq)': str(seq2),
                    '确认号(ack)': str(seq1 + 1),
                    '窗口大小': str(win_size),
                    '含义': '接收端确认收到SYN(ack=seq1+1)，同时发送自己的初始序列号'+str(seq2)
                },
                '第3次握手 (ACK)': {
                    '方向': f'{local_ip}:{local_port} → {target_host}:{target_port}',
                    '标志位': 'ACK=1',
                    '序列号(seq)': str(seq1 + 1),
                    '确认号(ack)': str(seq2 + 1),
                    '窗口大小': str(win_size),
                    '含义': '发送端确认收到SYN+ACK(ack=seq2+1)，连接正式建立'
                },
                '握手总结': [
                    ('SYN →', '发送端发起连接请求', 'seq='+str(seq1)),
                    ('← SYN+ACK', '接收端确认并发起连接', 'seq='+str(seq2)+', ack='+str(seq1+1)),
                    ('ACK →', '发送端确认连接', 'seq='+str(seq1+1)+', ack='+str(seq2+1)),
                ]
            }
        })

        try:
            sock.connect((target_host, target_port))
        except socket.timeout:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP连接超时: 无法连接到 {target_host}:{target_port}，请检查：1)目标主机是否可达 2)目标端口{target_port}是否开放 3)防火墙是否放行 4)接收端协商服务器是否启动', 'steps': result['steps']})
        except ConnectionRefusedError:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'连接被拒绝: {target_host}:{target_port}，目标端口未监听或服务未启动。请确认接收端容器已运行且协商服务器在端口{target_port}上监听', 'steps': result['steps']})
        except Exception as e:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP连接失败: {e}', 'steps': result['steps']})

        print(f"\n{'='*60}")
        print(f"  [步骤1] TCP 三次握手完成: {local_ip}:{local_port} → {target_host}:{target_port}")
        print(f"{'='*60}\n")

        # ================================================================
        # 步骤 2: 交换 RSA 公钥
        #   发送端发送自己的 RSA 公钥给接收端
        #   接收端返回自己的 RSA 公钥给发送端
        # ================================================================
        _connection_state['status'] = 'exchanging_rsa_keys'

        print(f"  [发送端-步骤2] 发送RSA公钥给 {target_host}:{target_port}...")

        my_rsa_pub = get_rsa_keys()[0]  # (e, n)

        # 发送本方 RSA 公钥
        step2_send = json.dumps({
            'type': 'step2_rsa_pub_exchange',
            'rsa_e': my_rsa_pub[0],
            'rsa_n': my_rsa_pub[1],
            'listen_port': LISTEN_PORT
        }).encode()
        sock.sendall(struct.pack('>I', len(step2_send)) + step2_send)
        print(f"  [发送端-步骤2] RSA公钥已发送，等待对方回复...")

        # 接收对方 RSA 公钥
        resp_len = struct.unpack('>I', _recv_exact(sock, 4))[0]
        resp_data = _recv_exact(sock, resp_len)
        peer_step2 = json.loads(resp_data.decode())
        print(f"  [发送端-步骤2] 收到对方RSA公钥")

        peer_rsa_e = peer_step2['rsa_e']
        peer_rsa_n = peer_step2['rsa_n']
        peer_rsa_pub = (peer_rsa_e, peer_rsa_n)
        peer_listen_port = peer_step2.get('listen_port', LISTEN_PORT)

        _connection_state['peer_listen_port'] = peer_listen_port
        _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}
        _connection_state['peer_public_key_raw'] = peer_rsa_pub

        result['steps'].append({
            'id': 2,
            'title': '步骤2: 交换 RSA 公钥',
            'status': 'success',
            'description': '双方互相发送各自的 RSA 公钥，为后续签名验证做准备',
            'detail': {
                '我发送的RSA公钥': {
                    'e (指数)': str(my_rsa_pub[0]),
                    'n (模数)': str(my_rsa_pub[1])[:64] + f"... ({my_rsa_pub[1].bit_length()}位)",
                    '说明': '用此公钥可以验证我对DH公钥的签名'
                },
                '收到的对方RSA公钥': {
                    'e (指数)': str(peer_rsa_e),
                    'n (模数)': str(peer_rsa_n)[:64] + f"... ({peer_rsa_n.bit_length()}位)",
                    '说明': '用此公钥验证对方的DH公钥签名'
                },
                '交换方向': '我 → 对方：我的RSA公钥 | 对方 → 我：对方的RSA公钥',
                '用途': '后续步骤中，双方用收到的对方RSA公钥来验证对方DH公钥的数字签名'
            }
        })

        print(f"{'='*60}")
        print(f"  [步骤2] RSA 公钥交换完成")
        print(f"    我的RSA公钥: e={my_rsa_pub[0]}, n={str(my_rsa_pub[1])[:32]}...({my_rsa_pub[1].bit_length()}位)")
        print(f"    对方RSA公钥: e={peer_rsa_e}, n={str(peer_rsa_n)[:32]}...({peer_rsa_n.bit_length()}位)")
        print(f"{'='*60}\n")

        # ================================================================
        # 步骤 3: 交换 DH 公钥（带 RSA 数字签名）
        #   双方各自生成 DH 密钥对
        #   用各自的 RSA 私钥对 DH 公钥签名（不可否认性 + 真实性）
        #   互相发送签名的 DH 公钥
        # ================================================================
        _connection_state['status'] = 'exchanging_dh_keys'

        # 生成 DH 密钥对
        _dh_peer = DHPeer(bits=256)
        my_dh_public = _dh_peer.get_public_key()
        my_dh_private = _dh_peer.private_key  # 保存私钥引用用于后续计算

        # 用本方 RSA 私钥对 DH 公钥签名
        my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
        my_signature = rsa_sign(my_dh_public_bytes, get_rsa_keys()[1])

        # 发送签名后的 DH 公钥
        step3_send = json.dumps({
            'type': 'step3_dh_key_exchange',
            'dh_public': hex(my_dh_public),
            'dh_signature': my_signature.hex()
        }).encode()
        sock.sendall(struct.pack('>I', len(step3_send)) + step3_send)
        print(f"  [发送端-步骤3] DH公钥+签名已发送，等待对方回复...")

        # 接收对方签名的 DH 公钥
        resp_len = struct.unpack('>I', _recv_exact(sock, 4))[0]
        resp_data = _recv_exact(sock, resp_len)
        peer_step3 = json.loads(resp_data.decode())
        print(f"  [发送端-步骤3] 收到对方DH公钥+签名")

        peer_dh_public = int(peer_step3['dh_public'], 16)
        peer_dh_signature = bytes.fromhex(peer_step3['dh_signature'])

        result['steps'].append({
            'id': 3,
            'title': '步骤3: 交换 DH 公钥（带 RSA 数字签名）',
            'status': 'success',
            'description': '双方生成 DH 密钥对，用各自的 RSA 私钥对 DH 公钥签名后发送',
            'detail': {
                '我生成的DH密钥对': {
                    'DH私钥(保密)': hex(_dh_peer.private_key)[:40] + '...',
                    'DH公钥(将发送)': hex(my_dh_public),
                    '说明': 'DH私钥绝不外泄，只有我知道'
                },
                '我对DH公钥的RSA签名': {
                    '原始数据': f'DH公钥字节({len(my_dh_public_bytes)}字节)',
                    '签名值': my_signature.hex()[:64] + '...',
                    '签名算法': 'SHA256(DH公钥) → RSA私钥加密哈希值',
                    '作用': '证明这个DH公钥确实来自我（不可否认性）'
                },
                '收到的对方DH公钥+签名': {
                    '对方DH公钥': hex(peer_dh_public),
                    '对方DH公钥签名': peer_dh_signature.hex()[:64] + '...',
                    '说明': '下一步将用对方RSA公钥验证此签名'
                },
                '交换方向': '我 → 对方：我的DH公钥+我的RSA签名 | 对方 → 我：对方的DH公钥+对方的RSA签名'
            }
        })

        print(f"{'='*60}")
        print(f"  [步骤3] DH 公钥交换完成")
        print(f"    我的DH公钥: {hex(my_dh_public)}")
        print(f"    我的签名:   {my_signature.hex()[:48]}...")
        print(f"    对方DH公钥: {hex(peer_dh_public)}")
        print(f"    对方签名:   {peer_dh_signature.hex()[:48]}...")
        print(f"{'='*60}\n")

        # ================================================================
        # 步骤 4: 验证对方签名
        #   用步骤2中收到的对方 RSA 公钥，验证步骤3中对方 DH 公钥的签名
        #   如果验证通过 → 对方的 DH 公钥是真实的（未被篡改）
        #   如果验证失败 → 可能遭受中间人攻击！
        # ================================================================
        _connection_state['status'] = 'verifying_signatures'

        peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')

        # 详细调试信息
        from sha256 import sha256 as _sha256_dbg
        actual_hash_dbg = int.from_bytes(_sha256_dbg(peer_dh_public_bytes), 'big')
        recovered_hash_dbg = pow(int.from_bytes(peer_dh_signature, 'big'), peer_rsa_e, peer_rsa_n)
        sig_match = (actual_hash_dbg == recovered_hash_dbg)

        print(f"{'='*60}")
        print(f"  [步骤4] 验证对方签名...")
        print(f"    对方DH公钥的SHA256哈希: {hex(actual_hash_dbg)}")
        print(f"    从签名恢复的哈希值:     {hex(recovered_hash_dbg)}")
        print(f"    匹配结果: {'✓ 通过' if sig_match else '✗ 失败'}")
        print(f"{'='*60}\n")

        peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)
        _connection_state['peer_verified'] = peer_verified

        if not peer_verified:
            result['steps'].append({
                'id': 4,
                'title': '步骤4: 验证对方签名',
                'status': 'error',
                'description': '用对方 RSA 公钥验证对方 DH 公钥的数字签名 — 失败！',
                'detail': {
                    '验证结果': '失败 ✗',
                    '错误原因': '对方DH公钥的签名无法用其RSA公钥验证通过',
                    '可能原因': [
                        '中间人攻击：有人篡改了DH公钥或签名',
                        '传输过程中数据损坏',
                        '对方使用了错误的RSA密钥对'
                    ],
                    '安全警告': '继续使用可能导致会话密钥泄露！连接已终止。'
                }
            })
            sock.close()
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': '对方签名验证失败！可能遭受中间人攻击', 'steps': result['steps']})

        result['steps'].append({
            'id': 4,
            'title': '步骤4: 验证对方签名',
            'status': 'success',
            'description': '用步骤2收到的对方 RSA 公钥，验证步骤3对方 DH 公钥的签名',
            'detail': {
                '验证对象': '对方发送的 DH 公钥 + 对方的 RSA 数字签名',
                '验证方法': [
                    '① 计算 SHA256(对方DH公钥) → 得到哈希值 H',
                    '② 用对方RSA公钥解密签名 → 得到 H\'',
                    '③ 比较 H == H\' ?'
                ],
                '验证结果': '通过 ✓',
                '实际哈希值(H)': hex(actual_hash_dbg),
                '从签名恢复的哈希值(H\')': hex(recovered_hash_dbg),
                '含义': '对方的 DH 公钥确实是用对方的 RSA 私钥签名的，真实可信',
                '安全性': '即使有人截获并篡改了 DH 公钥，没有私钥也无法伪造有效签名'
            }
        })

        print(f"  [步骤4] 签名验证通过 ✓\n")

        # ================================================================
        # 步骤 5: 计算共享会话密钥
        #   发送端: shared_secret = 对方DH公钥 ^ 我的DH私钥 mod p
        #   接收端: shared_secret = 我的DH公钥 ^ 对方DH私钥 mod p
        #   数学保证: 双方得到相同的 shared_secret !
        #   然后用 SHA-256 派生 AES 会话密钥 和 HMAC 密钥
        # ================================================================
        _dh_peer.compute_shared_secret(peer_dh_public)
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        _connection_state['session_key'] = session_key.hex()
        _connection_state['hmac_key'] = hmac_key.hex()
        _connection_state['status'] = 'connected'

        sock.close()  # 协商完成，关闭协商连接

        result['steps'].append({
            'id': 5,
            'title': '步骤5: 计算共享会话密钥',
            'status': 'success',
            'description': '双方利用 DH 算法独立计算出相同的共享密钥，派生 AES 加密密钥和 HMAC 认证密钥',
            'detail': {
                'DH共享秘密计算': {
                    '公式': 'shared_secret = 对方DH公钥 ^ 本方DH私钥 mod p',
                    '数学原理': '(g^b)^a mod p = (g^a)^b mod p = g^(ab) mod p',
                    '安全性': '即使窃听到双方的 DH 公钥，没有私钥也无法计算出共享秘密（离散对数难题）'
                },
                '密钥派生(SHA-256)': {
                    '输入': f'DH共享秘密({_dh_peer.shared_secret.bit_length()}位)',
                    '输出(32字节)': '前16字节 = AES-128-CBC密钥 | 后16字节 = HMAC-SHA256密钥',
                    'AES会话密钥': session_key.hex(),
                    'HMAC认证密钥': hmac_key.hex()
                },
                '最终结果': {
                    '状态': '连接已建立 ✓',
                    '可用操作': ['抓取数据包', '加密并发送数据(AES+HMAC+RSA签名)', '接收端自动解密验证']
                }
            }
        })

        result['success'] = True

        print(f"{'='*60}")
        print(f"  [步骤5] 会话密钥生成完成 ✓")
        print(f"    AES会话密钥: {session_key.hex()}")
        print(f"    HMAC密钥:    {hmac_key.hex()}")
        print(f"{'='*60}")
        print(f"\n  ★ 连接建立成功！可以进行加密通信了\n")

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        _connection_state['status'] = 'disconnected'
        # 确保关闭socket，防止接收端协商服务器卡死
        try:
            sock.close()
        except:
            pass
        return jsonify({'success': False, 'error': f'连接异常: {e}', 'detail': traceback.format_exc()})


@app.route('/api/debug_connect', methods=['POST'])
def debug_connect():
    """调试连接：逐步测试，返回每一步的详细结果"""
    try:
        data = request.get_json() or {}
        host = data.get('host', RECEIVER_HOST)
        port = int(data.get('port', LISTEN_PORT))
        results = []

        # 步骤1: TCP连接
        print(f"  [调试] 步骤1: TCP连接 {host}:{port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            results.append({'step': 'TCP连接', 'ok': True, 'detail': f'成功连接 {host}:{port}'})
        except socket.timeout:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': f'连接超时 {host}:{port}'})
            return jsonify({'success': False, 'results': results})
        except ConnectionRefusedError:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': f'连接被拒绝 {host}:{port}，对方9999端口未监听'})
            return jsonify({'success': False, 'results': results})
        except Exception as e:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': str(e)})
            return jsonify({'success': False, 'results': results})

        # 步骤2: 发送ping
        print(f"  [调试] 步骤2: 发送ping")
        try:
            ping_msg = json.dumps({'type': 'ping'}).encode()
            sock.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
            results.append({'step': '发送ping', 'ok': True, 'detail': '已发送ping请求'})
        except Exception as e:
            results.append({'step': '发送ping', 'ok': False, 'detail': str(e)})
            sock.close()
            return jsonify({'success': False, 'results': results})

        # 步骤3: 读取pong
        print(f"  [调试] 步骤3: 读取pong")
        try:
            pong_len_data = _recv_exact(sock, 4, timeout=5)
            pong_len = struct.unpack('>I', pong_len_data)[0]
            if pong_len > 10000:
                results.append({'step': '读取pong', 'ok': False, 'detail': f'响应长度异常: {pong_len}'})
                sock.close()
                return jsonify({'success': False, 'results': results})
            pong_data = _recv_exact(sock, pong_len, timeout=5)
            pong = json.loads(pong_data.decode())
            results.append({'step': '读取pong', 'ok': True, 'detail': f'对方模式: {pong.get("mode")}, 监听端口: {pong.get("listen_port")}'})
        except Exception as e:
            results.append({'step': '读取pong', 'ok': False, 'detail': f'读取pong失败: {e}'})
            sock.close()
            return jsonify({'success': False, 'results': results})

        sock.close()
        results.append({'step': '结论', 'ok': True, 'detail': 'TCP连接和协议通信均正常，可以尝试正式连接'})
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==================== 接收端协商服务 ====================

_negotiate_server_running = False


def start_negotiate_server():
    """启动接收端的协商服务器，等待发送端连接"""
    global _negotiate_server_running, _dh_peer, _connection_state

    if _negotiate_server_running:
        return

    def server_thread():
        global _dh_peer, _connection_state, _negotiate_server_status, _negotiate_server_running
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(300)
            server_sock.bind(('0.0.0.0', LISTEN_PORT))
            server_sock.listen(5)
            print(f"  [协商服务器] 监听 0.0.0.0:{LISTEN_PORT}")
            _negotiate_server_running = True
            _negotiate_server_status = {'running': True, 'port': LISTEN_PORT, 'error': None}
        except Exception as e:
            print(f"  [协商服务器] 启动失败: {e}")
            _negotiate_server_status = {'running': False, 'port': LISTEN_PORT, 'error': str(e)}
            _negotiate_server_running = False
            return

        while True:
            conn = None
            try:
                conn, addr = server_sock.accept()
                conn.settimeout(30)  # 关键：给每个连接设置30秒超时，防止卡死
                print(f"  [协商服务器] 收到来自 {addr} 的连接")

                # 先保存之前的状态，ping 不改变状态
                prev_status = _connection_state['status']
                _connection_state['peer_ip'] = addr[0]
                _connection_state['peer_port'] = addr[1]

                # 读取协商请求
                req_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                req_data = _recv_exact(conn, req_len)
                req = json.loads(req_data.decode())

                # 保存对方的监听端口
                peer_listen_port = req.get('listen_port', LISTEN_PORT)

                if req.get('type') == 'ping':
                    # 连通性测试，直接回复 pong，不改变连接状态
                    try:
                        pong = json.dumps({'type': 'pong', 'mode': MODE, 'listen_port': LISTEN_PORT}).encode()
                        conn.sendall(struct.pack('>I', len(pong)) + pong)
                    except:
                        pass  # 发送端可能已关闭，忽略
                    conn.close()
                    # 恢复之前的状态
                    _connection_state['status'] = prev_status
                    continue

                elif req.get('type') == 'data_transfer':
                    # 数据传输不改变连接状态
                    if _dh_peer and _dh_peer.get_session_key():
                        _handle_data_transfer(conn, req)
                    conn.close()
                    continue

                # 只有真正的密钥协商才设置状态
                _connection_state['status'] = 'negotiating'
                print(f"  [协商服务器] 开始密钥协商流程...")

                if req.get('type') == 'step2_rsa_pub_exchange':
                    # ========== 步骤2: 接收端处理 RSA 公钥交换 ==========
                    peer_rsa_e = req['rsa_e']
                    peer_rsa_n = req['rsa_n']
                    peer_listen_port = req.get('listen_port', LISTEN_PORT)
                    peer_rsa_pub = (peer_rsa_e, peer_rsa_n)

                    _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}
                    _connection_state['peer_public_key_raw'] = peer_rsa_pub
                    _connection_state['peer_listen_port'] = peer_listen_port

                    my_rsa_pub = get_rsa_keys()[0]
                    print(f"  [接收端-步骤2] RSA公钥交换完成")

                    # 返回自己的 RSA 公钥
                    step2_resp = json.dumps({
                        'type': 'step2_rsa_pub_exchange',
                        'rsa_e': my_rsa_pub[0],
                        'rsa_n': my_rsa_pub[1],
                        'listen_port': LISTEN_PORT
                    }).encode()
                    conn.sendall(struct.pack('>I', len(step2_resp)) + step2_resp)

                    # 等待步骤3：DH 公钥交换
                    resp_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                    resp_data = _recv_exact(conn, resp_len)
                    step3_req = json.loads(resp_data.decode())

                    if step3_req.get('type') != 'step3_dh_key_exchange':
                        print(f"  [协商服务器] 收到未知请求类型: {step3_req.get('type')}, 忽略")
                        conn.close()
                        continue

                    # ========== 步骤3: 接收端处理 DH 公钥交换 ==========
                    peer_dh_public = int(step3_req['dh_public'], 16)
                    peer_dh_signature = bytes.fromhex(step3_req['dh_signature'])

                    _dh_peer = DHPeer(bits=256)
                    my_dh_public = _dh_peer.get_public_key()

                    my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
                    my_signature = rsa_sign(my_dh_public_bytes, get_rsa_keys()[1])

                    print(f"  [接收端-步骤3] DH公钥交换完成")

                    step3_resp = json.dumps({
                        'type': 'step3_dh_key_exchange',
                        'dh_public': hex(my_dh_public),
                        'dh_signature': my_signature.hex()
                    }).encode()
                    conn.sendall(struct.pack('>I', len(step3_resp)) + step3_resp)

                    # ========== 步骤4: 验证对方签名 ==========
                    peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')
                    peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)
                    _connection_state['peer_verified'] = peer_verified

                    print(f"  [接收端-步骤4] 签名验证: {'通过' if peer_verified else '失败'}")

                    if peer_verified:
                        # ========== 步骤5: 计算共享会话密钥 ==========
                        _dh_peer.compute_shared_secret(peer_dh_public)
                        session_key = _dh_peer.get_session_key()
                        hmac_key = _dh_peer.get_hmac_key()

                        _connection_state['session_key'] = session_key.hex()
                        _connection_state['hmac_key'] = hmac_key.hex()
                        _connection_state['status'] = 'connected'

                        print(f"  [接收端-步骤5] 会话密钥生成完成 ✓ 连接已建立!")
                    else:
                        _connection_state['status'] = 'disconnected'
                        print(f"  [接收端] 签名验证失败，连接拒绝")

                conn.close()

            except socket.timeout:
                # accept 超时，继续等待
                continue
            except ConnectionError as e:
                print(f"  [协商服务器] 连接断开: {e}")
                if conn:
                    try: conn.close()
                    except: pass
                # 连接断开不改变状态，继续等待新连接
                continue
            except Exception as e:
                print(f"  [协商服务器] 处理错误: {e}")
                import traceback
                traceback.print_exc()
                if conn:
                    try: conn.close()
                    except: pass
                continue

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()


def _handle_data_transfer(conn, req):
    """处理数据传输（含 RSA 签名验证），可视化解密过程"""
    global _received_data
    try:
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        print(f"  [数据传输] 开始接收加密数据...")

        # 读取加密数据
        data_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
        print(f"  [数据传输] 加密数据包长度: {data_len}")
        encrypted_packet = _recv_exact(conn, data_len)

        # 读取 RSA 签名
        sig_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
        print(f"  [数据传输] 签名长度: {sig_len}")
        signature = _recv_exact(conn, sig_len)

        # 解析数据包
        from network import unpack_packet
        ct, _, _, recv_iv, recv_hmac = unpack_packet(encrypted_packet)

        # 构建可视化步骤
        steps = []

        # 步骤1: 接收加密数据
        steps.append({
            'id': 1, 'title': '接收加密数据包',
            'description': '从TCP连接中读取发送端传来的加密数据包和数字签名',
            'data': {
                '加密数据包长度': f'{data_len} 字节',
                '密文长度': f'{len(ct)} 字节',
                '签名长度': f'{sig_len} 字节',
                '发送端IP': _connection_state.get('peer_ip', '未知'),
            }
        })

        # 步骤2: HMAC验证
        computed_hmac = hmac_sha256(hmac_key, ct)
        hmac_valid = (computed_hmac == recv_hmac)
        steps.append({
            'id': 2, 'title': 'HMAC-SHA256 完整性验证',
            'description': '用DH协商派生的HMAC密钥重新计算HMAC，与收到的HMAC比对',
            'data': {
                'HMAC密钥来源': 'DH密钥协商派生',
                'HMAC密钥': hmac_key.hex(),
                '收到的HMAC': recv_hmac.hex(),
                '计算的HMAC': computed_hmac.hex(),
                '验证结果': '通过 - 数据完整' if hmac_valid else '失败 - 数据可能被篡改！',
            },
            'status': 'success' if hmac_valid else 'error'
        })

        # 步骤3: RSA签名验证
        sig_verified = rsa_verify(ct, signature, _connection_state.get('peer_public_key_raw', get_rsa_keys()[0]))
        steps.append({
            'id': 3, 'title': 'RSA 数字签名验证（不可否认性）',
            'description': '用发送端RSA公钥验证签名，确保数据来源真实且不可否认',
            'data': {
                '签名算法': 'RSA-SHA256',
                '验证流程': 'SHA-256(密文) → 用发送端公钥解密签名 → 比对',
                '签名值(前64字节)': signature.hex()[:64] + '...',
                '发送端公钥e': str(_connection_state.get('peer_public_key', {}).get('e', '未知')),
                '验证结果': '通过 - 来源真实' if sig_verified else '失败 - 数据来源不可信！',
            },
            'status': 'success' if sig_verified else 'error'
        })

        # 步骤4: AES解密
        decrypted = aes_decrypt(ct, session_key, mode='cbc', iv=recv_iv)
        decrypted_text = decrypted.decode('utf-8')
        steps.append({
            'id': 4, 'title': 'AES-128-CBC 解密',
            'description': '用DH协商得出的会话密钥解密密文，还原原始数据',
            'data': {
                '会话密钥来源': 'DH密钥协商',
                'AES密钥': session_key.hex(),
                'IV': recv_iv.hex() if recv_iv else '',
                '密文(前128字节)': ct.hex()[:128] + '...',
                '解密后长度': f'{len(decrypted_text)} 字符',
                '解密结果': '成功' if hmac_valid and sig_verified else '解密完成但验证未通过',
            },
            'status': 'success' if hmac_valid and sig_verified else 'error'
        })

        # 步骤5: 保存解密数据
        filepath = os.path.join(DATA_DIR, 'latest_received.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(decrypted_text)

        steps.append({
            'id': 5, 'title': '保存解密数据',
            'description': '将解密后的原始数据保存到文件',
            'data': {
                '保存路径': os.path.abspath(filepath),
                '数据长度': f'{len(decrypted_text)} 字符',
                '数据预览': decrypted_text[:300] + ('...' if len(decrypted_text) > 300 else ''),
            }
        })

        record = {
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'hmac_valid': hmac_valid,
            'sig_verified': sig_verified,
            'decrypted_data': decrypted_text,
            'saved_to': os.path.abspath(filepath),
            'session_key_hex': session_key.hex(),
            'hmac_key_hex': hmac_key.hex(),
            'iv_hex': recv_iv.hex() if recv_iv else '',
            'hmac_value': recv_hmac.hex(),
            'signature_hex': signature.hex()[:64] + '...',
            'steps': steps,
        }

        if not hmac_valid or not sig_verified:
            record['error'] = ''
            if not hmac_valid:
                record['error'] += 'HMAC验证失败，数据可能被篡改！'
            if not sig_verified:
                record['error'] += ' RSA签名验证失败，数据来源不可信！'

        _received_data.append(record)

    except Exception as e:
        _received_data.append({
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'hmac_valid': False,
            'sig_verified': False,
            'error': str(e),
            'steps': [{
                'id': 0, 'title': '接收失败',
                'description': '处理数据传输时发生异常',
                'data': {'错误信息': str(e)},
                'status': 'error'
            }]
        })


def _recv_exact(sock, n, timeout=30):
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

@app.route('/api/capture_diag', methods=['GET'])
def capture_diag():
    """抓包诊断：检查scapy状态、网卡接口等"""
    result = {'scapy_available': HAS_SCAPY, 'issues': [], 'ifaces': []}
    if not HAS_SCAPY:
        result['issues'].append('scapy未安装')
        return jsonify(result)

    try:
        from scapy.all import get_if_list, get_if_addr, conf, IFACES

        # 检查scapy接口列表
        result['scapy_conf_iface'] = str(conf.iface)
        result['scapy_ifaces_detail'] = {}

        for iface_name in get_if_list():
            try:
                ip = get_if_addr(str(iface_name))
                result['ifaces'].append({'name': str(iface_name), 'ip': ip})
            except:
                result['ifaces'].append({'name': str(iface_name), 'ip': 'ERROR'})

        # 检查IFACES对象
        try:
            for k, v in IFACES.items():
                result['scapy_ifaces_detail'][str(k)] = {'name': str(v.name) if hasattr(v, 'name') else str(k), 'ip': str(v.ip) if hasattr(v, 'ip') else 'N/A'}
        except:
            pass

        # 自动选择接口测试
        from capture import _auto_select_interface
        selected = _auto_select_interface()
        result['auto_selected_iface'] = selected

        if not selected:
            result['issues'].append('无法自动选择网卡接口')

        # 尝试抓1个包测试
        try:
            from scapy.all import sniff
            test_kwargs = {'count': 1, 'timeout': 3, 'store': False}
            if selected:
                test_kwargs['iface'] = selected
            sniff(**test_kwargs)
            result['sniff_test'] = 'OK - scapy可以抓包'
        except Exception as e:
            result['sniff_test'] = f'FAIL - {e}'
            result['issues'].append(f'scapy sniff测试失败: {e}')

    except Exception as e:
        result['issues'].append(f'诊断异常: {e}')

    return jsonify(result)


@app.route('/api/capture', methods=['POST'])
def api_capture():
    """抓取网络数据包（详细版，包含抓包过程日志）"""
    try:
        count = request.json.get('count', 10) if request.is_json else 10
        timeout = request.json.get('timeout', 15) if request.is_json else 15
        # 支持自定义BPF过滤器，默认捕获所有IP流量
        filter_rule = request.json.get('filter', 'ip') if request.is_json else 'ip'
        interface = request.json.get('interface', None) if request.is_json else None

        print(f"  [抓包] 开始: count={count}, timeout={timeout}, filter={filter_rule}, interface={interface}")

        packets, capture_log = capture_packets(count=count, timeout=timeout,
                                                interface=interface,
                                                filter_rule=filter_rule)

        print(f"  [抓包] 完成: 抓到 {len(packets)} 个包")

        if not packets:
            return jsonify({'success': False, 'error': '未抓取到任何数据包（可能网络无流量或过滤器太严格）', 'capture_log': capture_log})

        # 每次抓包覆盖写入固定文件（latest_capture.json）
        json_data = packets_to_json(packets)
        filepath = os.path.join(DATA_DIR, 'latest_capture.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(json_data)

        return jsonify({
            'success': True,
            'packets': packets,
            'count': len(packets),
            'json_data': json_data,
            'saved_to': os.path.abspath(filepath),
            'filename': 'latest_capture.json',
            'capture_log': capture_log
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e), 'detail': traceback.format_exc()})


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
        sock.settimeout(30)
        try:
            print(f"  [发送端] 连接 {target_host}:{target_port} 发送加密数据...")
            sock.connect((target_host, target_port))
            # 发送数据传输请求
            req = json.dumps({'type': 'data_transfer'}).encode()
            sock.sendall(struct.pack('>I', len(req)) + req)
            # 发送加密数据包
            sock.sendall(struct.pack('>I', len(packet)) + packet)
            # 发送签名
            sock.sendall(struct.pack('>I', len(signature)) + signature)
            send_success = True
            print(f"  [发送端] 加密数据发送成功! 数据包{len(packet)}字节, 签名{len(signature)}字节")
        except Exception as e:
            send_success = False
            result['error'] = f'发送失败: {e}'
            print(f"  [发送端] 发送失败: {e}")
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


@app.route('/api/data_files')
def list_data_files():
    """列出所有抓包数据文件和接收数据文件"""
    files = []
    data_dir = os.path.abspath(DATA_DIR)
    if os.path.isdir(data_dir):
        for f in sorted(os.listdir(data_dir), reverse=True):
            fp = os.path.join(data_dir, f)
            if os.path.isfile(fp):
                stat = os.stat(fp)
                files.append({
                    'name': f,
                    'path': fp,
                    'size': stat.st_size,
                    'size_human': f"{stat.st_size / 1024:.1f}KB" if stat.st_size > 1024 else f"{stat.st_size}B",
                    'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                    'type': 'capture' if f.startswith('capture_') else 'received' if f.startswith('received_') else 'other'
                })
    return jsonify({'data_dir': data_dir, 'files': files, 'total': len(files)})


@app.route('/api/data_files/<filename>')
def get_data_file(filename):
    """查看指定数据文件内容"""
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.isfile(filepath):
        return jsonify({'error': '文件不存在'}), 404
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    return jsonify({'filename': filename, 'path': os.path.abspath(filepath), 'content': content})


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
        # 额外测试: 跨密钥验证应失败
        pub2, priv2 = generate_keypair(RSA_BITS)
        sig2 = rsa_sign(td, priv2)
        cross_verified = rsa_verify(td, sig2, pub)
        results['RSA+签名'] = 'PASS' if dec == td and verified and not cross_verified else 'FAIL'
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


@app.route('/api/restart_negotiate', methods=['POST'])
def restart_negotiate():
    """重启协商服务器（如果崩溃或端口异常时使用）"""
    global _negotiate_server_running, _negotiate_server_status
    # 强制重置状态，允许重新启动
    _negotiate_server_running = False
    _negotiate_server_status = {'running': False, 'port': LISTEN_PORT, 'error': None}
    time.sleep(0.3)  # 等旧线程退出
    start_negotiate_server()
    time.sleep(0.5)  # 等新服务器启动
    return jsonify({
        'success': True,
        'negotiate_server': _negotiate_server_status,
        'message': '协商服务器已重启'
    })


@app.route('/api/reset_connection', methods=['POST'])
def reset_connection():
    """重置连接状态（断开当前连接）"""
    global _dh_peer, _connection_state
    _dh_peer = None
    _connection_state = {
        'status': 'disconnected',
        'peer_ip': None,
        'peer_port': None,
        'tcp_handshake': [],
        'dh_exchange': [],
        'session_key': None,
        'hmac_key': None,
        'peer_public_key': None,
        'peer_verified': False,
    }
    return jsonify({'success': True, 'message': '连接已重置'})


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
