"""
Flask Web Application - Network Security Transmission Demo System
Complete flow: TCP connection -> DH key negotiation (with signature) -> Data encryption -> Verification and decryption
"""
import os
import sys
import json
import time
import socket
import struct
import threading
import random

APP_VERSION = '3.0.0'

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request

from aes import aes_encrypt, aes_decrypt
from rsa import generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_sign, rsa_verify, save_keypair
from sha256 import sha256
from hmac_sha256 import hmac_sha256
from dh import DHPeer
from capture import capture_packets, packets_to_json, get_network_info, HAS_SCAPY

app = Flask(__name__)
# 修改 Jinja2 分隔符，避免与 Vue 3 的 {{ }} 冲突
app.jinja_env.variable_start_string = '[['
app.jinja_env.variable_end_string = ']]'

# 全局异常处理，避免 Internal Server Error 无详细信息
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    tb = traceback.format_exc()
    print(f"[ERROR] {request.path}: {e}\n{tb}")
    return jsonify({'success': False, 'error': str(e), 'traceback': tb}), 500

# 禁用API响应缓存，确保前端实时刷新
@app.after_request
def add_no_cache_headers(response):
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

MODE = os.environ.get('MODE', 'sender') or 'sender'
RECEIVER_HOST = os.environ.get('RECEIVER_HOST', '127.0.0.1') or '127.0.0.1'
RECEIVER_PORT = int(os.environ.get('RECEIVER_PORT', '9999') or '9999')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT', '9999') or '9999')
RSA_BITS = int(os.environ.get('RSA_BITS', '1024') or '1024')
DATA_DIR = os.environ.get('DATA_DIR', './captured_data') or './captured_data'
FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0') or '0.0.0.0'
FLASK_PORT = int(os.environ.get('FLASK_PORT', '5000') or '5000')

os.makedirs(DATA_DIR, exist_ok=True)

_rsa_keys = None
_rsa_lock = threading.Lock()
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
    'peer_listen_port': None,
    'peer_public_key_raw': None,
}
_latest_received = None
_key_files = {'pub': None, 'priv': None, 'dh_priv': None, 'dh_pub': None}
_negotiate_server_status = {'running': False, 'port': None, 'error': None}
_negotiate_steps = []
_negotiate_server_running = False
_negotiate_server_sock = None
_negotiate_server_thread = None
_active_conn = None       # 当前活跃的协商连接 socket，用于强制关闭
_active_conn_lock = threading.Lock()

# 心跳检测：当连接建立后定期检测对方是否在线
_heartbeat_thread = None
_heartbeat_running = False
_heartbeat_fail_count = 0
_HEARTBEAT_INTERVAL = 3   # 心跳间隔（秒）
_HEARTBEAT_TIMEOUT = 5    # 单次心跳超时（秒）
_HEARTBEAT_MAX_FAIL = 3   # 连续失败次数阈值


def _get_local_ip():
    for target in ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect((target, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and ip != '127.0.0.1':
                return ip
        except:
            try: s.close()
            except: pass
    return '127.0.0.1'


def get_rsa_keys():
    global _rsa_keys, _key_files
    with _rsa_lock:
        if _rsa_keys is None:
            _rsa_keys = generate_keypair(RSA_BITS)
            pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                                prefix=os.path.join(DATA_DIR, 'rsa_key'))
            _key_files['pub'] = os.path.abspath(pub_path)
            _key_files['priv'] = os.path.abspath(priv_path)
    return _rsa_keys


def _save_dh_keys():
    global _key_files
    if _dh_peer:
        dh_priv_path = os.path.join(DATA_DIR, 'dh_private_key.txt')
        dh_pub_path = os.path.join(DATA_DIR, 'dh_public_key.txt')
        with open(dh_priv_path, 'w') as f:
            f.write(hex(_dh_peer.private_key))
        with open(dh_pub_path, 'w') as f:
            f.write(hex(_dh_peer.public_key))
        _key_files['dh_priv'] = os.path.abspath(dh_priv_path)
        _key_files['dh_pub'] = os.path.abspath(dh_pub_path)


def _reset_connection_state():
    global _dh_peer, _connection_state
    _stop_heartbeat()  # 停止心跳检测
    _dh_peer = None
    _connection_state.update({
        'status': 'disconnected',
        'peer_ip': None,
        'peer_port': None,
        'tcp_handshake': [],
        'dh_exchange': [],
        'session_key': None,
        'hmac_key': None,
        'peer_public_key': None,
        'peer_verified': False,
        'peer_listen_port': None,
        'peer_public_key_raw': None,
    })


def _notify_peer_disconnect():
    """Notify the connected peer that we are disconnecting (bidirectional disconnect sync)."""
    peer_ip = _connection_state.get('peer_ip')
    peer_port = _connection_state.get('peer_listen_port')
    if not peer_ip or not peer_port:
        return
    try:
        notify_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        notify_sock.settimeout(3)
        notify_sock.connect((peer_ip, int(peer_port)))
        msg = json.dumps({'type': 'disconnect_notify', 'reason': 'peer_initiated'}).encode()
        notify_sock.sendall(struct.pack('>I', len(msg)) + msg)
        try:
            resp_len_data = _recv_exact(notify_sock, 4, timeout=3)
            resp_len = struct.unpack('>I', resp_len_data)[0]
            if resp_len > 0 and resp_len < 10000:
                _recv_exact(notify_sock, resp_len, timeout=3)
        except:
            pass
        notify_sock.close()
    except:
        pass


# ==================== Heartbeat Detection ====================

def _start_heartbeat():
    """启动心跳检测线程，定期检测对方是否在线"""
    global _heartbeat_thread, _heartbeat_running, _heartbeat_fail_count
    _stop_heartbeat()  # 先停止旧的
    _heartbeat_fail_count = 0
    _heartbeat_running = True

    def heartbeat_loop():
        global _heartbeat_fail_count, _heartbeat_running
        print("  [Heartbeat] 心跳检测线程已启动")
        while _heartbeat_running and _connection_state.get('status') == 'connected':
            time.sleep(_HEARTBEAT_INTERVAL)
            if not _heartbeat_running or _connection_state.get('status') != 'connected':
                break

            peer_ip = _connection_state.get('peer_ip')
            peer_port = _connection_state.get('peer_listen_port')
            if not peer_ip or not peer_port:
                _heartbeat_fail_count += 1
            else:
                # 发送 TCP ping 检测对方是否在线
                try:
                    ping_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ping_sock.settimeout(_HEARTBEAT_TIMEOUT)
                    ping_sock.connect((peer_ip, int(peer_port)))
                    ping_msg = json.dumps({'type': 'ping'}).encode()
                    ping_sock.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
                    # 等待 pong 响应
                    resp_len_data = _recv_exact(ping_sock, 4, timeout=_HEARTBEAT_TIMEOUT)
                    resp_len = struct.unpack('>I', resp_len_data)[0]
                    if 0 < resp_len < 10000:
                        resp_data = _recv_exact(ping_sock, resp_len, timeout=_HEARTBEAT_TIMEOUT)
                        resp = json.loads(resp_data.decode())
                        if resp.get('type') == 'pong':
                            _heartbeat_fail_count = 0
                    ping_sock.close()
                except Exception as e:
                    _heartbeat_fail_count += 1
                    print(f"  [Heartbeat] ping 失败 ({_heartbeat_fail_count}/{_HEARTBEAT_MAX_FAIL}): {e}")

            # 连续失败超过阈值，标记断开
            if _heartbeat_fail_count >= _HEARTBEAT_MAX_FAIL:
                print(f"  [Heartbeat] 连续 {_heartbeat_fail_count} 次心跳失败，标记连接断开")
                _connection_state['status'] = 'disconnected'
                _heartbeat_running = False
                break

        print("  [Heartbeat] 心跳检测线程已退出")

    _heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    _heartbeat_thread.start()


def _stop_heartbeat():
    """停止心跳检测线程"""
    global _heartbeat_running, _heartbeat_thread
    _heartbeat_running = False
    if _heartbeat_thread and _heartbeat_thread.is_alive():
        _heartbeat_thread.join(timeout=2)
    _heartbeat_thread = None

@app.route('/')
def index():
    return render_template('index.html')


# ==================== Info API ====================

@app.route('/api/info')
def get_info():
    net_info = get_network_info()
    pub_key, priv_key = get_rsa_keys()
    e, n = pub_key
    d, _ = priv_key

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

    if _dh_peer:
        key_info['dh'] = {
            'private_key': hex(_dh_peer.private_key),
            'public_key': hex(_dh_peer.public_key),
            'shared_secret': hex(_dh_peer.shared_secret) if _dh_peer.shared_secret else None,
            'private_key_file': _key_files.get('dh_priv', ''),
            'public_key_file': _key_files.get('dh_pub', ''),
        }
    if _connection_state.get('session_key'):
        key_info['session'] = {
            'aes_key': _connection_state['session_key'],
            'hmac_key': _connection_state['hmac_key'],
        }

    return jsonify({
        'version': APP_VERSION,
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
        'received_count': 1 if _latest_received else 0,
        'negotiate_server': _negotiate_server_status,
    })


@app.route('/api/health')
def health_check():
    result = {
        'negotiate_server': _negotiate_server_status,
        'listen_port': LISTEN_PORT,
        'port_listening': False,
        'scapy_available': HAS_SCAPY,
        'network_debug': {},
    }
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(1)
        test_sock.connect(('127.0.0.1', LISTEN_PORT))
        test_sock.close()
        result['port_listening'] = True
    except:
        result['port_listening'] = False

    try:
        result['network_debug']['hostname'] = socket.gethostname()
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
    try:
        data = request.get_json() or {}
        host = data.get('host', RECEIVER_HOST)
        port = int(data.get('port', LISTEN_PORT))
        results = []

        import re
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', host)
        if is_ip:
            results.append({'step': 'DNS解析', 'ok': True, 'detail': f'{host} 是IP地址，无需DNS解析'})
        else:
            try:
                resolved_ip = socket.gethostbyname(host)
                results.append({'step': 'DNS解析', 'ok': True, 'detail': f'{host} -> {resolved_ip}'})
            except Exception as e:
                results.append({'step': 'DNS解析', 'ok': False, 'detail': str(e)})
                return jsonify({'success': False, 'results': results, 'error': 'DNS解析失败'})

        start = time.time()
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            test_sock.connect((host, port))
            latency = round((time.time() - start) * 1000, 1)
            test_sock.close()
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': True, 'detail': f'成功，延迟 {latency}ms'})
        except socket.timeout:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': '超时(3秒)'})
            return jsonify({'success': False, 'results': results, 'error': 'TCP连接超时'})
        except ConnectionRefusedError:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': '连接被拒绝'})
            return jsonify({'success': False, 'results': results, 'error': '连接被拒绝'})
        except Exception as e:
            results.append({'step': f'TCP连接 {host}:{port}', 'ok': False, 'detail': str(e)})
            return jsonify({'success': False, 'results': results, 'error': str(e)})

        try:
            test_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock2.settimeout(5)
            test_sock2.connect((host, port))
            ping_msg = json.dumps({'type': 'ping'}).encode()
            test_sock2.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
            pong_len = struct.unpack('>I', _recv_exact(test_sock2, 4))[0]
            pong_data = _recv_exact(test_sock2, pong_len)
            pong = json.loads(pong_data.decode())
            test_sock2.close()
            if pong.get('type') == 'pong':
                results.append({'step': '协议通信', 'ok': True, 'detail': f"对方模式: {pong.get('mode','?')}, 监听端口: {pong.get('listen_port','?')}"})
            else:
                results.append({'step': '协议通信', 'ok': False, 'detail': f"异常响应: {pong}"})
        except Exception as e:
            results.append({'step': '协议通信', 'ok': False, 'detail': str(e)})

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/set_mode', methods=['POST'])
def set_mode():
    global MODE, _negotiate_server_running, _connection_state, _negotiate_server_thread, _negotiate_steps, _dh_peer, _rsa_keys, _latest_received
    data = request.get_json() or {}
    new_mode = data.get('mode', '')
    if new_mode not in ('sender', 'receiver'):
        return jsonify({'success': False, 'error': '模式必须是 sender 或 receiver'})
    if new_mode == MODE:
        return jsonify({'success': True, 'mode': MODE, 'message': f'已经是{"发送端" if MODE=="sender" else "接收端"}模式'})

    # 1. 通知对端断开连接
    if _connection_state['status'] == 'connected':
        _notify_peer_disconnect()

    # 2. 完全重置连接状态
    _reset_connection_state()
    _negotiate_steps = []
    _latest_received = None

    # 3. 重新生成所有密钥（RSA + DH），确保干净状态
    with _rsa_lock:
        _rsa_keys = generate_keypair(RSA_BITS)
        pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                            prefix=os.path.join(DATA_DIR, 'rsa_key'))
        _key_files['pub'] = os.path.abspath(pub_path)
        _key_files['priv'] = os.path.abspath(priv_path)
    _dh_peer = None

    # 3. 停止旧的协商服务器（确保完全停止后再启动新的）
    _stop_negotiate_server()

    # 4. 切换模式
    MODE = new_mode

    # 5. 仅接收端启动协商服务器，发送端不需要监听
    negotiate_msg = ''
    if MODE == 'receiver':
        start_negotiate_server()
        # start_negotiate_server 内部已通过 server_ready.wait() 同步等待
        if _negotiate_server_status.get('running'):
            negotiate_msg = '，协商服务器已启动'
        elif _negotiate_server_status.get('error'):
            negotiate_msg = f'，协商服务器启动失败: {_negotiate_server_status["error"]}'
        else:
            negotiate_msg = '，协商服务器启动中...'

    result = {'success': True, 'mode': MODE, 'negotiate_server': _negotiate_server_status, 'message': f'已切换为{"发送端" if MODE=="sender" else "接收端"}模式，密钥已重新生成' + negotiate_msg}
    if MODE == 'receiver' and not _negotiate_server_status.get('running'):
        result['success'] = False
        result['error'] = f"协商服务器启动失败: {_negotiate_server_status.get('error', '端口可能被占用')}"
    return jsonify(result)


# ==================== Key Management API ====================

@app.route('/api/regenerate_keys', methods=['POST'])
def regenerate_keys():
    """重新随机生成所有密钥（RSA + DH），并重置连接状态。"""
    global _rsa_keys, _dh_peer, _key_files, _connection_state, _negotiate_steps, _latest_received
    try:
        # 重置连接状态
        _reset_connection_state()
        _negotiate_steps = []
        _latest_received = None

        # 重新生成RSA密钥
        with _rsa_lock:
            _rsa_keys = generate_keypair(RSA_BITS)
            pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                                prefix=os.path.join(DATA_DIR, 'rsa_key'))
            _key_files['pub'] = os.path.abspath(pub_path)
            _key_files['priv'] = os.path.abspath(priv_path)

        # 重置DH（下次连接时自动生成）
        _dh_peer = None

        return jsonify({
            'success': True,
            'message': f'所有密钥已随机重新生成（RSA {RSA_BITS}位）',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==================== Connection API ====================

@app.route('/api/connect', methods=['POST'])
def api_connect():
    """Sender: Establish TCP connection + complete 5-step key exchange."""
    global _dh_peer, _connection_state

    try:
        data = request.get_json() or {}
        target_host = data.get('host', RECEIVER_HOST)
        target_port = int(data.get('port', RECEIVER_PORT))

        if _connection_state['status'] == 'connected':
            return jsonify({'success': False, 'error': '已处于连接状态，请先断开当前连接'})

        _connection_state['status'] = 'connecting'
        _connection_state['peer_ip'] = target_host
        _connection_state['peer_port'] = target_port
        _connection_state['tcp_handshake'] = []
        _connection_state['dh_exchange'] = []

        result = {'steps': [], 'success': False}

        # Step 1: TCP Three-way Handshake
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
        sock.settimeout(30)

        seq1 = random.randint(100000000, 999999999)
        seq2 = random.randint(100000000, 999999999)
        win_size = random.choice([8192, 16384, 32768, 65535])
        mss = 1460

        handshake_info = [
            {'step': 1, 'dir': '->', 'from': f'{local_ip}:{local_port}', 'to': f'{target_host}:{target_port}',
             'flag': 'SYN', 'desc': '发送 SYN 报文'},
            {'step': 2, 'dir': '<-', 'from': f'{target_host}:{target_port}', 'to': f'{local_ip}:{local_port}',
             'flag': 'SYN+ACK', 'desc': '接收 SYN+ACK 报文'},
            {'step': 3, 'dir': '->', 'from': f'{local_ip}:{local_port}', 'to': f'{target_host}:{target_port}',
             'flag': 'ACK', 'desc': '发送 ACK 报文，连接建立'},
        ]
        _connection_state['tcp_handshake'] = handshake_info

        result['steps'].append({
            'id': 1,
            'title': '第1步：TCP 三次握手',
            'status': 'success',
            'description': '与接收端建立可靠的 TCP 连接',
            'detail': {
                '连接参数': {
                    '发送端（本机）': f'{local_ip}:{local_port}',
                    '接收端（目标）': f'{target_host}:{target_port}',
                    '协议': 'TCP',
                    '窗口大小': str(win_size),
                    'MSS': str(mss)
                },
                '第一次握手（SYN）': {
                    '方向': f'{local_ip}:{local_port} -> {target_host}:{target_port}',
                    '标志位': 'SYN=1',
                    '序列号': str(seq1),
                    '确认号': '0',
                    '含义': '发送端请求建立连接，初始序列号=' + str(seq1)
                },
                '第二次握手（SYN+ACK）': {
                    '方向': f'{target_host}:{target_port} -> {local_ip}:{local_port}',
                    '标志位': 'SYN=1, ACK=1',
                    '序列号': str(seq2),
                    '确认号': str(seq1 + 1),
                    '含义': '接收端确认 SYN，发送自己的序列号=' + str(seq2)
                },
                '第三次握手（ACK）': {
                    '方向': f'{local_ip}:{local_port} -> {target_host}:{target_port}',
                    '标志位': 'ACK=1',
                    '序列号': str(seq1 + 1),
                    '确认号': str(seq2 + 1),
                    '含义': '发送端确认，TCP连接建立完成'
                },
            }
        })

        try:
            sock.connect((target_host, target_port))
        except socket.timeout:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP连接超时：无法连接到 {target_host}:{target_port}', 'steps': result['steps']})
        except ConnectionRefusedError:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'连接被拒绝：{target_host}:{target_port}，请确认接收端协商服务器已启动', 'steps': result['steps']})
        except Exception as e:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP连接失败：{e}', 'steps': result['steps']})

        # Step 2: RSA Public Key Exchange
        _connection_state['status'] = 'exchanging_rsa_keys'
        my_rsa_pub = get_rsa_keys()[0]
        my_rsa_priv = get_rsa_keys()[1]

        step2_send = json.dumps({
            'type': 'step2_rsa_pub_exchange',
            'rsa_e': my_rsa_pub[0],
            'rsa_n': my_rsa_pub[1],
            'listen_port': LISTEN_PORT,
        }).encode()
        sock.sendall(struct.pack('>I', len(step2_send)) + step2_send)

        resp_len = struct.unpack('>I', _recv_exact(sock, 4))[0]
        resp_data = _recv_exact(sock, resp_len)
        peer_step2 = json.loads(resp_data.decode())

        peer_rsa_e = peer_step2['rsa_e']
        peer_rsa_n = peer_step2['rsa_n']
        peer_rsa_pub = (peer_rsa_e, peer_rsa_n)

        _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}
        _connection_state['peer_public_key_raw'] = peer_rsa_pub
        _connection_state['peer_listen_port'] = peer_step2.get('listen_port', LISTEN_PORT)

        result['steps'].append({
            'id': 2,
            'title': '第2步：RSA 公钥交换',
            'status': 'success',
            'description': '双方交换 RSA 公钥，用于后续签名验证',
            'detail': {
                '本机 RSA 公钥': {
                    'e（指数）': str(my_rsa_pub[0]),
                    'n（模数）': str(my_rsa_pub[1])[:64] + f"... ({my_rsa_pub[1].bit_length()} 位)",
                },
                '对方 RSA 公钥': {
                    'e（指数）': str(peer_rsa_e),
                    'n（模数）': str(peer_rsa_n)[:64] + f"... ({peer_rsa_n.bit_length()} 位)",
                },
                '用途': '用于验证下一步中 DH 公钥的 RSA 数字签名'
            }
        })

        # Step 3: DH Public Key Exchange with RSA Signature
        _connection_state['status'] = 'exchanging_dh_keys'

        if not _dh_peer or _dh_peer.shared_secret is not None:
            _dh_peer = DHPeer()
            _save_dh_keys()
        my_dh_public = _dh_peer.get_public_key()

        my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
        my_signature = rsa_sign(my_dh_public_bytes, my_rsa_priv)

        step3_send = json.dumps({
            'type': 'step3_dh_key_exchange',
            'dh_public': hex(my_dh_public),
            'dh_signature': my_signature.hex()
        }).encode()
        sock.sendall(struct.pack('>I', len(step3_send)) + step3_send)

        resp_len = struct.unpack('>I', _recv_exact(sock, 4))[0]
        resp_data = _recv_exact(sock, resp_len)
        peer_step3 = json.loads(resp_data.decode())

        peer_dh_public = int(peer_step3['dh_public'], 16)
        peer_dh_signature = bytes.fromhex(peer_step3['dh_signature'])

        result['steps'].append({
            'id': 3,
            'title': '第3步：DH 公钥交换（带 RSA 签名）',
            'status': 'success',
            'description': '交换 DH 公钥，并用 RSA 私钥对 DH 公钥签名',
            'detail': {
                '本机 DH 密钥对': {
                    'DH 私钥（保密）': hex(_dh_peer.private_key)[:40] + '...',
                    'DH 公钥': hex(my_dh_public),
                },
                '本机 RSA 签名（对 DH 公钥）': {
                    '签名值': my_signature.hex()[:64] + '...',
                    '算法': 'SHA256(DH公钥) -> RSA签名(哈希)',
                },
                '对方 DH 公钥': hex(peer_dh_public),
                '对方 RSA 签名': peer_dh_signature.hex()[:64] + '...',
            }
        })

        # Step 4: Verify Peer Signature
        _connection_state['status'] = 'verifying_signatures'

        peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')

        from sha256 import sha256 as _sha256_dbg
        actual_hash_dbg = int.from_bytes(_sha256_dbg(peer_dh_public_bytes), 'big')
        recovered_hash_dbg = pow(int.from_bytes(peer_dh_signature, 'big'), peer_rsa_e, peer_rsa_n)
        # 当n小于哈希值时，对哈希值取模n后再比较（与rsa_verify逻辑一致）
        sig_match = (actual_hash_dbg % peer_rsa_n == recovered_hash_dbg) if actual_hash_dbg >= peer_rsa_n else (actual_hash_dbg == recovered_hash_dbg)

        peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)
        _connection_state['peer_verified'] = peer_verified

        if not peer_verified:
            result['steps'].append({
                'id': 4,
                'title': '第4步：验证对方签名',
                'status': 'error',
                'description': 'RSA 签名验证失败',
                'detail': {
                    '结果': '失败',
                    '可能原因': '中间人攻击或数据损坏'
                }
            })
            sock.close()
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': '对方签名验证失败！可能存在中间人攻击', 'steps': result['steps']})

        result['steps'].append({
            'id': 4,
            'title': '第4步：验证对方签名',
            'status': 'success',
            'description': '使用对方 RSA 公钥验证其 DH 公钥的数字签名',
            'detail': {
                '验证方法': [
                    '1. 计算 SHA256(对方DH公钥) -> H',
                    '2. 用对方 RSA 公钥解密签名 -> H\'',
                    '3. 比较 H == H\''
                ],
                '结果': '通过',
                '实际哈希值 (H)': hex(actual_hash_dbg),
                '恢复哈希值 (H\')': hex(recovered_hash_dbg),
                '含义': '对方 DH 公钥是真实的，未被篡改'
            }
        })

        # Step 5: Compute Shared Session Key
        _dh_peer.compute_shared_secret(peer_dh_public)
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        _connection_state['session_key'] = session_key.hex()
        _connection_state['hmac_key'] = hmac_key.hex()
        _connection_state['status'] = 'connected'
        _start_heartbeat()  # 启动心跳检测

        sock.close()

        result['steps'].append({
            'id': 5,
            'title': '第5步：计算共享会话密钥',
            'status': 'success',
            'description': '双方独立计算相同的 DH 共享秘密，派生 AES 和 HMAC 密钥',
            'detail': {
                'DH 共享秘密计算': {
                    '公式': 'shared_secret = 对方DH公钥 ^ 本机DH私钥 mod p',
                    '数学原理': '(g^b)^a mod p = (g^a)^b mod p = g^(ab) mod p',
                    '安全性': '离散对数问题使窃听者无法计算共享秘密'
                },
                '密钥派生（SHA-256）': {
                    '输入': f'DH 共享秘密（{_dh_peer.shared_secret.bit_length()} 位）',
                    '输出（32字节）': '前16字节 = AES-128-CBC 密钥 | 后16字节 = HMAC-SHA256 密钥',
                    'AES 会话密钥': session_key.hex(),
                    'HMAC 密钥': hmac_key.hex()
                },
                '结果': {
                    '状态': '连接建立成功',
                }
            }
        })

        result['success'] = True
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        _connection_state['status'] = 'disconnected'
        try:
            sock.close()
        except:
            pass
        return jsonify({'success': False, 'error': f'连接错误：{e}', 'detail': traceback.format_exc()})


@app.route('/api/debug_connect', methods=['POST'])
def debug_connect():
    try:
        data = request.get_json() or {}
        host = data.get('host', RECEIVER_HOST)
        port = int(data.get('port', LISTEN_PORT))
        results = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            results.append({'step': 'TCP连接', 'ok': True, 'detail': f'已连接到 {host}:{port}'})
        except socket.timeout:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': f'连接超时 {host}:{port}'})
            return jsonify({'success': False, 'results': results})
        except ConnectionRefusedError:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': f'连接被拒绝 {host}:{port}'})
            return jsonify({'success': False, 'results': results})
        except Exception as e:
            results.append({'step': 'TCP连接', 'ok': False, 'detail': str(e)})
            return jsonify({'success': False, 'results': results})

        try:
            ping_msg = json.dumps({'type': 'ping'}).encode()
            sock.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
            results.append({'step': '发送Ping', 'ok': True, 'detail': 'Ping已发送'})
        except Exception as e:
            results.append({'step': '发送Ping', 'ok': False, 'detail': str(e)})
            sock.close()
            return jsonify({'success': False, 'results': results})

        try:
            pong_len_data = _recv_exact(sock, 4, timeout=5)
            pong_len = struct.unpack('>I', pong_len_data)[0]
            if pong_len > 10000:
                results.append({'step': '读取Pong', 'ok': False, 'detail': f'异常长度: {pong_len}'})
                sock.close()
                return jsonify({'success': False, 'results': results})
            pong_data = _recv_exact(sock, pong_len, timeout=5)
            pong = json.loads(pong_data.decode())
            results.append({'step': '读取Pong', 'ok': True, 'detail': f"对方模式: {pong.get('mode')}, 监听端口: {pong.get('listen_port')}"})
        except Exception as e:
            results.append({'step': '读取Pong', 'ok': False, 'detail': f'失败: {e}'})
            sock.close()
            return jsonify({'success': False, 'results': results})

        sock.close()
        results.append({'step': '结论', 'ok': True, 'detail': 'TCP和协议通信正常，可以进行完整连接'})
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/connection_status')
def connection_status():
    return jsonify({
        **_connection_state,
        'negotiate_steps': _negotiate_steps,
    })


@app.route('/api/reset_connection', methods=['POST'])
def reset_connection():
    """断开连接，通知对方，重置所有状态。"""
    global _negotiate_steps, _latest_received, _dh_peer, _rsa_keys
    if _connection_state['status'] == 'connected':
        _notify_peer_disconnect()
    _reset_connection_state()
    _negotiate_steps = []
    _latest_received = None
    # 重新生成密钥，确保下次连接使用新密钥
    _dh_peer = None
    with _rsa_lock:
        _rsa_keys = generate_keypair(RSA_BITS)
        pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                            prefix=os.path.join(DATA_DIR, 'rsa_key'))
        _key_files['pub'] = os.path.abspath(pub_path)
        _key_files['priv'] = os.path.abspath(priv_path)
    return jsonify({'success': True, 'message': '连接已断开，密钥已重新生成', 'status': _connection_state['status']})


@app.route('/api/restart_negotiate', methods=['POST'])
def restart_negotiate():
    global _negotiate_server_running, _negotiate_server_status, _negotiate_server_sock, _negotiate_steps, _connection_state, _dh_peer, _rsa_keys, _latest_received, _negotiate_server_thread
    # 重置连接状态和协商步骤
    _reset_connection_state()
    _negotiate_steps = []
    _latest_received = None
    _dh_peer = None

    # 重新生成RSA密钥
    with _rsa_lock:
        _rsa_keys = generate_keypair(RSA_BITS)
        pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                            prefix=os.path.join(DATA_DIR, 'rsa_key'))
        _key_files['pub'] = os.path.abspath(pub_path)
        _key_files['priv'] = os.path.abspath(priv_path)

    # 安全停止旧协商服务器
    _stop_negotiate_server()

    # 仅接收端启动协商服务器
    if MODE == 'receiver':
        start_negotiate_server()

    result = {'success': True, 'negotiate_server': _negotiate_server_status, 'status': _connection_state['status']}
    if MODE == 'receiver' and not _negotiate_server_status.get('running'):
        result['success'] = False
        result['error'] = f"协商服务器启动失败: {_negotiate_server_status.get('error', '未知错误')}"
    return jsonify(result)


# ==================== Receiver Negotiation Server ====================

def _stop_negotiate_server():
    """安全停止协商服务器，确保旧线程完全退出、端口释放。"""
    global _negotiate_server_running, _negotiate_server_sock, _negotiate_server_thread, _negotiate_server_status, _active_conn

    _negotiate_server_running = False

    # 先关闭活跃连接，让阻塞在 recv 上的线程退出
    with _active_conn_lock:
        if _active_conn:
            try:
                _active_conn.close()
            except:
                pass
            _active_conn = None

    # 关闭 server socket，让 accept() 抛出 OSError 从而退出循环
    if _negotiate_server_sock:
        try:
            _negotiate_server_sock.close()
        except:
            pass
        _negotiate_server_sock = None

    # 等待旧线程完全退出（最多8秒）
    if _negotiate_server_thread and _negotiate_server_thread.is_alive():
        _negotiate_server_thread.join(timeout=8)
        if _negotiate_server_thread.is_alive():
            print("  [Negotiate Server] WARNING: Old thread still alive after 8s join")
    _negotiate_server_thread = None

    # 额外等待端口释放
    time.sleep(1)

    _negotiate_server_status = {'running': False, 'port': None, 'error': None}


def start_negotiate_server():
    global _negotiate_server_running, _dh_peer, _connection_state, _negotiate_server_sock, _negotiate_server_thread

    if _negotiate_server_running:
        return

    # 关闭旧socket
    if _negotiate_server_sock:
        try:
            _negotiate_server_sock.close()
        except:
            pass
        _negotiate_server_sock = None

    # 用 Event 同步等待服务器绑定端口成功
    server_ready = threading.Event()
    server_error = [None]  # 用列表传递异常信息

    def server_thread():
        global _dh_peer, _connection_state, _negotiate_server_status, _negotiate_server_running, _negotiate_steps, _negotiate_server_sock, _active_conn
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(3)  # 短超时，确保能快速响应停止信号
            # 端口绑定重试（最多5次，每次间隔2秒）
            bind_ok = False
            for attempt in range(5):
                try:
                    server_sock.bind(('0.0.0.0', LISTEN_PORT))
                    bind_ok = True
                    break
                except OSError as be:
                    print(f"  [Negotiate Server] Bind attempt {attempt+1}/5 failed: {be}")
                    if attempt < 4:
                        time.sleep(2)
            if not bind_ok:
                raise OSError(f"端口 {LISTEN_PORT} 绑定失败（重试5次后仍被占用）")
            server_sock.listen(5)
            _negotiate_server_sock = server_sock
            print(f"  [Negotiate Server] Listening on 0.0.0.0:{LISTEN_PORT}")
            _negotiate_server_running = True
            _negotiate_server_status = {'running': True, 'port': LISTEN_PORT, 'error': None}
            server_ready.set()  # 通知主线程：服务器已就绪
        except Exception as e:
            print(f"  [Negotiate Server] Failed to start: {e}")
            _negotiate_server_status = {'running': False, 'port': LISTEN_PORT, 'error': str(e)}
            _negotiate_server_running = False
            server_error[0] = e
            server_ready.set()  # 即使失败也要通知，避免主线程死等
            return

        while _negotiate_server_running:
            conn = None
            try:
                conn, addr = server_sock.accept()
                conn.settimeout(30)
                print(f"  [Negotiate Server] Connection from {addr}")

                # 跟踪活跃连接，以便停止服务器时能强制关闭
                with _active_conn_lock:
                    _active_conn = conn

                prev_status = _connection_state['status']
                prev_peer_ip = _connection_state['peer_ip']
                prev_peer_port = _connection_state['peer_port']

                req_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                req_data = _recv_exact(conn, req_len)
                req = json.loads(req_data.decode())

                # Handle disconnect notification (bidirectional sync)
                if req.get('type') == 'disconnect_notify':
                    print(f"  [Negotiate Server] Received disconnect notification from {addr}")
                    _reset_connection_state()
                    _negotiate_steps = []
                    try:
                        ack = json.dumps({'type': 'disconnect_ack'}).encode()
                        conn.sendall(struct.pack('>I', len(ack)) + ack)
                    except:
                        pass
                    conn.close()
                    continue

                # Handle ping — 不修改连接状态
                if req.get('type') == 'ping':
                    try:
                        pong = json.dumps({'type': 'pong', 'mode': MODE, 'listen_port': LISTEN_PORT}).encode()
                        conn.sendall(struct.pack('>I', len(pong)) + pong)
                    except:
                        pass
                    conn.close()
                    continue

                # Handle data transfer — 不修改连接状态中的 peer_ip/peer_port
                elif req.get('type') == 'data_transfer':
                    if _dh_peer and _dh_peer.get_session_key():
                        _handle_data_transfer(conn, req)
                    else:
                        print(f"  [Negotiate Server] Data transfer rejected: no session key")
                        try:
                            err = json.dumps({'type': 'error', 'message': 'No session key'}).encode()
                            conn.sendall(struct.pack('>I', len(err)) + err)
                        except:
                            pass
                    conn.close()
                    continue

                # Key negotiation — 更新连接状态
                _connection_state['peer_ip'] = addr[0]
                _connection_state['peer_port'] = addr[1]
                _connection_state['status'] = 'negotiating'
                _negotiate_steps = []

                _negotiate_steps.append({
                    'id': 1,
                    'title': '第1步：TCP 三次握手',
                    'status': 'success',
                    'description': '发送端发起 TCP 连接，三次握手已完成',
                    'detail': {
                        '连接参数': {
                            '发送端（对方）': f'{addr[0]}:{addr[1]}',
                            '接收端（本机）': f'{_get_local_ip()}:{LISTEN_PORT}',
                            '协议': 'TCP',
                        },
                    }
                })

                if req.get('type') == 'step2_rsa_pub_exchange':
                    # Step 2: RSA Public Key Exchange
                    peer_rsa_e = req['rsa_e']
                    peer_rsa_n = req['rsa_n']
                    peer_listen_port = req.get('listen_port', LISTEN_PORT)
                    peer_rsa_pub = (peer_rsa_e, peer_rsa_n)

                    _connection_state['peer_public_key'] = {'e': peer_rsa_e, 'n_bits': peer_rsa_n.bit_length()}
                    _connection_state['peer_public_key_raw'] = peer_rsa_pub
                    _connection_state['peer_listen_port'] = peer_listen_port

                    my_rsa_pub = get_rsa_keys()[0]

                    _negotiate_steps.append({
                        'id': 2,
                        'title': '第2步：RSA 公钥交换',
                        'status': 'success',
                        'description': '收到发送端 RSA 公钥，发送了本机 RSA 公钥',
                        'detail': {
                            '对方 RSA 公钥': {
                                'e（指数）': str(peer_rsa_e),
                                'n（模数）': str(peer_rsa_n)[:64] + f"... ({peer_rsa_n.bit_length()} 位)",
                            },
                            '本机 RSA 公钥': {
                                'e（指数）': str(my_rsa_pub[0]),
                                'n（模数）': str(my_rsa_pub[1])[:64] + f"... ({my_rsa_pub[1].bit_length()} 位)",
                            },
                        }
                    })

                    step2_resp = json.dumps({
                        'type': 'step2_rsa_pub_exchange',
                        'rsa_e': my_rsa_pub[0],
                        'rsa_n': my_rsa_pub[1],
                        'listen_port': LISTEN_PORT,
                    }).encode()
                    conn.sendall(struct.pack('>I', len(step2_resp)) + step2_resp)

                    # Step 3: Receive DH key exchange
                    dh_req_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
                    dh_req_data = _recv_exact(conn, dh_req_len)
                    dh_req = json.loads(dh_req_data.decode())

                    peer_dh_public = int(dh_req['dh_public'], 16)
                    peer_dh_signature = bytes.fromhex(dh_req['dh_signature'])

                    if not _dh_peer or _dh_peer.shared_secret is not None:
                        _dh_peer = DHPeer()
                    my_dh_public = _dh_peer.get_public_key()
                    my_dh_private = _dh_peer.private_key
                    _save_dh_keys()

                    my_dh_public_bytes = my_dh_public.to_bytes((my_dh_public.bit_length() + 7) // 8, 'big')
                    my_signature = rsa_sign(my_dh_public_bytes, get_rsa_keys()[1])

                    step3_resp = json.dumps({
                        'type': 'step3_dh_key_exchange',
                        'dh_public': hex(my_dh_public),
                        'dh_signature': my_signature.hex()
                    }).encode()
                    conn.sendall(struct.pack('>I', len(step3_resp)) + step3_resp)

                    _negotiate_steps.append({
                        'id': 3,
                        'title': '第3步：DH 公钥交换（带 RSA 签名）',
                        'status': 'success',
                        'description': '交换了 DH 公钥及 RSA 签名',
                        'detail': {
                            '本机 DH 公钥': hex(my_dh_public),
                            '本机 RSA 签名': my_signature.hex()[:64] + '...',
                            '对方 DH 公钥': hex(peer_dh_public),
                            '对方 RSA 签名': peer_dh_signature.hex()[:64] + '...',
                        }
                    })

                    # Step 4: Verify Peer Signature
                    peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')

                    from sha256 import sha256 as _sha256_dbg
                    actual_hash_dbg = int.from_bytes(_sha256_dbg(peer_dh_public_bytes), 'big')
                    recovered_hash_dbg = pow(int.from_bytes(peer_dh_signature, 'big'), peer_rsa_e, peer_rsa_n)

                    peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)
                    _connection_state['peer_verified'] = peer_verified

                    if peer_verified:
                        _negotiate_steps.append({
                            'id': 4,
                            'title': '第4步：验证对方签名',
                            'status': 'success',
                            'description': '对方 DH 公钥签名验证通过',
                            'detail': {
                                '验证方法': [
                                    '1. 计算 SHA256(对方DH公钥) -> H',
                                    '2. 用对方 RSA 公钥解密签名 -> H\'',
                                    '3. 比较 H == H\''
                                ],
                                '结果': '通过',
                                '实际哈希值 (H)': hex(actual_hash_dbg),
                                '恢复哈希值 (H\')': hex(recovered_hash_dbg),
                            }
                        })
                    else:
                        _negotiate_steps.append({
                            'id': 4,
                            'title': '第4步：验证对方签名',
                            'status': 'error',
                            'description': '对方签名验证失败',
                            'detail': {
                                '结果': '失败',
                                '警告': '可能存在中间人攻击或数据损坏'
                            }
                        })
                        _connection_state['status'] = 'disconnected'
                        conn.close()
                        continue

                    if peer_verified:
                        # Step 5: Compute Shared Session Key
                        _dh_peer.compute_shared_secret(peer_dh_public)
                        session_key = _dh_peer.get_session_key()
                        hmac_key = _dh_peer.get_hmac_key()

                        _connection_state['session_key'] = session_key.hex()
                        _connection_state['hmac_key'] = hmac_key.hex()
                        _connection_state['status'] = 'connected'
                        _start_heartbeat()  # 启动心跳检测

                        _negotiate_steps.append({
                            'id': 5,
                            'title': '第5步：计算共享会话密钥',
                            'status': 'success',
                            'description': '双方计算了相同的共享秘密，派生了 AES 和 HMAC 密钥',
                            'detail': {
                                'DH 共享秘密': {
                                    '公式': 'shared_secret = 对方DH公钥 ^ 本机DH私钥 mod p',
                                    '安全性': '离散对数问题'
                                },
                                '密钥派生（SHA-256）': {
                                    'AES 会话密钥': session_key.hex(),
                                    'HMAC 密钥': hmac_key.hex()
                                },
                                '结果': {
                                    '状态': '连接建立成功',
                                }
                            }
                        })

                conn.close()

            except socket.timeout:
                # 超时时检查是否需要停止
                if not _negotiate_server_running:
                    break
                # 超时时如果状态卡在协商中，重置为未连接
                if _connection_state['status'] not in ('connected', 'disconnected'):
                    _connection_state['status'] = 'disconnected'
            except OSError:
                # socket被关闭（模式切换/重启），正常退出
                if not _negotiate_server_running:
                    break
            except ConnectionError as e:
                print(f"  [Negotiate Server] Connection error: {e}")
                # 连接错误时重置状态
                if _connection_state['status'] not in ('connected', 'disconnected'):
                    _connection_state['status'] = 'disconnected'
                if conn:
                    try: conn.close()
                    except: pass
            except Exception as e:
                print(f"  [Negotiate Server] Error: {e}")
                import traceback
                traceback.print_exc()
                # 异常时重置状态
                if _connection_state['status'] not in ('connected', 'disconnected'):
                    _connection_state['status'] = 'disconnected'
                if conn:
                    try: conn.close()
                    except: pass
            finally:
                # 每次连接处理完毕后清除活跃连接引用
                with _active_conn_lock:
                    if _active_conn is conn:
                        _active_conn = None

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    global _negotiate_server_thread
    _negotiate_server_thread = thread

    # 等待服务器绑定端口成功或失败（最多10秒）
    server_ready.wait(timeout=10)
    if server_error[0]:
        print(f"  [Negotiate Server] Startup failed: {server_error[0]}")
    elif not _negotiate_server_running:
        print(f"  [Negotiate Server] Startup timed out")
    else:
        print(f"  [Negotiate Server] Started successfully")


def _handle_data_transfer(conn, req):
    global _latest_received
    try:
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        data_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
        encrypted_packet = _recv_exact(conn, data_len)

        sig_len = struct.unpack('>I', _recv_exact(conn, 4))[0]
        signature = _recv_exact(conn, sig_len)

        from network import unpack_packet
        ct, _, _, recv_iv, recv_hmac = unpack_packet(encrypted_packet)

        steps = []

        steps.append({
            'id': 1, 'title': '接收加密数据',
            'description': '收到发送端的加密数据包和数字签名',
            'data': {
                '加密数据包长度': f'{data_len} 字节',
                '密文长度': f'{len(ct)} 字节',
                '签名长度': f'{sig_len} 字节',
                '发送端 IP': _connection_state.get('peer_ip', '未知'),
            }
        })

        computed_hmac = hmac_sha256(hmac_key, ct)
        hmac_valid = (computed_hmac == recv_hmac)
        steps.append({
            'id': 2, 'title': 'HMAC-SHA256 完整性验证',
            'description': '用 DH 派生的密钥重新计算 HMAC，与收到的 HMAC 比较',
            'data': {
                'HMAC 密钥': hmac_key.hex(),
                '收到的 HMAC': recv_hmac.hex(),
                '计算的 HMAC': computed_hmac.hex(),
                '结果': '通过 - 数据完整' if hmac_valid else '失败 - 数据可能被篡改！',
            },
            'status': 'success' if hmac_valid else 'error'
        })

        peer_rsa_pub = _connection_state.get('peer_public_key_raw')
        if peer_rsa_pub:
            sig_verified = rsa_verify(ct, signature, peer_rsa_pub)
        else:
            sig_verified = False
        steps.append({
            'id': 3, 'title': 'RSA 数字签名验证',
            'description': '用发送端 RSA 公钥验证签名，确保不可否认性',
            'data': {
                '算法': 'RSA-SHA256',
                '对方公钥': '已获取' if peer_rsa_pub else '未获取（无法验证）',
                '结果': '通过 - 来源可信' if sig_verified else '失败 - 来源不可信！',
            },
            'status': 'success' if sig_verified else 'error'
        })

        decrypted = aes_decrypt(ct, session_key, mode='cbc', iv=recv_iv)
        decrypted_text = decrypted.decode('utf-8')
        steps.append({
            'id': 4, 'title': 'AES-128-CBC 解密',
            'description': '用 DH 派生的会话密钥解密密文',
            'data': {
                'AES 密钥': session_key.hex(),
                'IV': recv_iv.hex() if recv_iv else '',
                '密文（前128字节）': ct.hex()[:128] + '...',
                '解密后长度': f'{len(decrypted_text)} 字符',
                '结果': '成功' if hmac_valid and sig_verified else '已解密但验证失败',
            },
            'status': 'success' if hmac_valid and sig_verified else 'error'
        })

        filepath = os.path.join(DATA_DIR, 'latest_received.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(decrypted_text)

        steps.append({
            'id': 5, 'title': '保存解密数据',
            'description': '将解密后的数据保存到文件',
            'data': {
                '保存路径': os.path.abspath(filepath),
                '数据长度': f'{len(decrypted_text)} 字符',
                '预览': decrypted_text[:300] + ('...' if len(decrypted_text) > 300 else ''),
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
            'steps': steps,
        }

        if not hmac_valid or not sig_verified:
            record['error'] = ''
            if not hmac_valid:
                record['error'] += 'HMAC验证失败！ '
            if not sig_verified:
                record['error'] += 'RSA签名验证失败！ '

        _latest_received = record

        # 发送确认响应给发送端
        try:
            ack_msg = json.dumps({
                'type': 'data_ack',
                'success': hmac_valid and sig_verified,
                'hmac_valid': hmac_valid,
                'sig_verified': sig_verified,
            }).encode()
            conn.sendall(struct.pack('>I', len(ack_msg)) + ack_msg)
        except:
            pass

    except Exception as e:
        _latest_received = {
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'hmac_valid': False,
            'sig_verified': False,
            'error': str(e),
            'steps': [{
                'id': 0, 'title': '接收失败',
                'description': '数据传输过程中发生异常',
                'data': {'错误': str(e)},
                'status': 'error'
            }]
        }
        # 发送错误确认给发送端
        try:
            err_ack = json.dumps({'type': 'data_ack', 'success': False, 'error': str(e)}).encode()
            conn.sendall(struct.pack('>I', len(err_ack)) + err_ack)
        except:
            pass


def _recv_exact(sock, n, timeout=30):
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("连接已关闭")
        data += chunk
    return data


# ==================== Capture API ====================

@app.route('/api/capture', methods=['POST'])
def api_capture():
    try:
        data = request.get_json() or {}
        count = int(data.get('count', 5))
        timeout = int(data.get('timeout', 20))
        filter_rule = data.get('filter', 'ip')

        if not HAS_SCAPY:
            return jsonify({'success': False, 'error': 'scapy不可用'})

        packets_info, capture_log = capture_packets(count=count, timeout=timeout, filter_rule=filter_rule)

        json_data = packets_to_json(packets_info)
        # 固定文件名，每次覆盖写入
        filepath = os.path.join(DATA_DIR, 'capture_latest.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(json_data)

        return jsonify({
            'success': True,
            'count': len(packets_info),
            'packets': packets_info,
            'json_data': json_data,
            'saved_to': os.path.abspath(filepath),
            'capture_log': capture_log,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/capture_diag', methods=['GET'])
def capture_diag():
    result = {'scapy_available': HAS_SCAPY, 'issues': [], 'ifaces': [], 'auto_selected_iface': None}
    if not HAS_SCAPY:
        result['issues'].append('scapy未安装')
        return jsonify(result)

    try:
        from scapy.all import get_if_list, get_if_addr, conf
        result['scapy_conf_iface'] = str(conf.iface)

        for iface_name in get_if_list():
            try:
                ip = get_if_addr(str(iface_name))
                result['ifaces'].append({'name': str(iface_name), 'ip': ip})
            except:
                result['ifaces'].append({'name': str(iface_name), 'ip': '不可用'})

        from capture import _auto_select_interface
        auto_iface = _auto_select_interface()
        result['auto_selected_iface'] = auto_iface

        sniff_test = '未测试'
        if auto_iface:
            try:
                from scapy.all import sniff as _sniff
                pkts = _sniff(count=1, timeout=3, iface=auto_iface, store=False)
                sniff_test = '成功 - 可以抓包'
            except Exception as e:
                sniff_test = f'失败: {e}'
        result['sniff_test'] = sniff_test

    except Exception as e:
        result['issues'].append(str(e))

    return jsonify(result)


# ==================== Send Data API ====================

@app.route('/api/send', methods=['POST'])
def api_send():
    """Sender: Encrypt data with AES+HMAC+RSA signature and send to receiver."""
    global _latest_received
    try:
        data = request.get_json() or {}
        plaintext = data.get('data', '')
        if not plaintext:
            return jsonify({'success': False, 'error': '没有可发送的数据'})

        if not _dh_peer or not _dh_peer.get_session_key():
            return jsonify({'success': False, 'error': '未连接，请先建立连接'})

        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()
        peer_ip = _connection_state.get('peer_ip')
        peer_port = _connection_state.get('peer_listen_port') or RECEIVER_PORT

        if not peer_ip:
            return jsonify({'success': False, 'error': '没有对方连接信息'})

        steps = []

        # Step 1: AES-128-CBC Encryption
        iv = os.urandom(16)
        ciphertext, iv_used = aes_encrypt(plaintext.encode('utf-8'), session_key, mode='cbc', iv=iv)
        steps.append({
            'id': 1, 'title': 'AES-128-CBC 加密',
            'description': '用 DH 派生的会话密钥加密明文',
            'detail': {
                'AES 密钥': session_key.hex(),
                'IV': iv_used.hex(),
                '明文长度': f'{len(plaintext)} 字符',
                '密文长度': f'{len(ciphertext)} 字节',
            }
        })

        # Step 2: HMAC-SHA256 Authentication
        hmac_value = hmac_sha256(hmac_key, ciphertext)
        steps.append({
            'id': 2, 'title': 'HMAC-SHA256 认证',
            'description': '计算密文的 HMAC 值，用于完整性验证',
            'detail': {
                'HMAC 密钥': hmac_key.hex(),
                'HMAC 值': hmac_value.hex(),
                '用途': '确保传输过程中数据完整性',
            }
        })

        # Step 3: RSA Digital Signature
        my_rsa_priv = get_rsa_keys()[1]
        signature = rsa_sign(ciphertext, my_rsa_priv)
        steps.append({
            'id': 3, 'title': 'RSA 数字签名',
            'description': '用 RSA 私钥对密文签名，确保不可否认性',
            'detail': {
                '签名算法': 'RSA-SHA256',
                '签名值': signature.hex()[:64] + '...',
                '用途': '确保数据真实性和不可否认性',
            }
        })

        # Step 4: Pack and Send
        from network import pack_packet
        peer_rsa_pub = _connection_state.get('peer_public_key_raw')
        # 用对方RSA公钥加密AES/HMAC密钥（混合加密：RSA加密对称密钥）
        # 如果对方RSA密钥太小（n < 128位），无法加密16字节的AES密钥，则跳过
        encrypted_aes_key = b''
        encrypted_hmac_key = b''
        rsa_enc_note = ''
        if peer_rsa_pub:
            peer_n = peer_rsa_pub[1]
            try:
                if peer_n.bit_length() >= 128:
                    encrypted_aes_key = rsa_encrypt_bytes(session_key, peer_rsa_pub)
                    encrypted_hmac_key = rsa_encrypt_bytes(hmac_key, peer_rsa_pub)
                    rsa_enc_note = f'已用对方RSA公钥({peer_n.bit_length()}位)加密'
                else:
                    rsa_enc_note = f'对方RSA公钥仅{peer_n.bit_length()}位，小于AES密钥128位，跳过RSA加密（已由DH密钥交换保障安全）'
            except Exception as e:
                rsa_enc_note = f'RSA加密跳过: {e}（已由DH密钥交换保障安全）'

        packet = pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=iv_used)
        step4_detail = {
            '数据包大小': f'{len(packet)} 字节',
            '目标': f'{peer_ip}:{peer_port}',
            '加密的 AES 密钥长度': f'{len(encrypted_aes_key)} 字节',
            '加密的 HMAC 密钥长度': f'{len(encrypted_hmac_key)} 字节',
        }
        if rsa_enc_note:
            step4_detail['RSA加密对称密钥'] = rsa_enc_note
        steps.append({
            'id': 4, 'title': '打包并发送',
            'description': '将加密数据打包，通过 TCP 发送',
            'detail': step4_detail
        })

        # Send via TCP
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_sock.settimeout(10)
        try:
            send_sock.connect((peer_ip, int(peer_port)))
            transfer_msg = json.dumps({'type': 'data_transfer'}).encode()
            send_sock.sendall(struct.pack('>I', len(transfer_msg)) + transfer_msg)
            send_sock.sendall(struct.pack('>I', len(packet)) + packet)
            send_sock.sendall(struct.pack('>I', len(signature)) + signature)

            # 等待接收端确认
            recv_ack_detail = ''
            try:
                ack_len_data = _recv_exact(send_sock, 4, timeout=5)
                ack_len = struct.unpack('>I', ack_len_data)[0]
                if ack_len > 0 and ack_len < 10000:
                    ack_data = _recv_exact(send_sock, ack_len, timeout=5)
                    ack = json.loads(ack_data.decode())
                    if ack.get('type') == 'data_ack':
                        recv_ack_detail = f"接收端确认: HMAC={'通过' if ack.get('hmac_valid') else '失败'}, 签名={'通过' if ack.get('sig_verified') else '失败'}"
            except:
                recv_ack_detail = '未收到接收端确认（数据可能已送达）'

            send_sock.close()
        except Exception as e:
            return jsonify({'success': False, 'error': f'发送失败：{e}', 'steps': steps})

        steps.append({
            'id': 5, 'title': '发送完成',
            'description': '加密数据已成功发送',
            'detail': {
                '状态': '成功',
                '发送目标': f'{peer_ip}:{peer_port}',
                '接收端确认': recv_ack_detail or '未收到确认',
            }
        })

        return jsonify({'success': True, 'steps': steps})

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'detail': traceback.format_exc()})


# ==================== Received Data API ====================

@app.route('/api/received_data')
def received_data():
    return jsonify({
        'count': 1 if _latest_received else 0,
        'data': [_latest_received] if _latest_received else [],
    })


# ==================== Algorithm Test API ====================

@app.route('/api/test_algo', methods=['POST'])
def test_algo():
    results = {}
    try:
        from sha256 import sha256 as _sha256
        test_msg = b"test_message_123"
        h = _sha256(test_msg)
        results['SHA-256'] = '通过' if len(h) == 32 else '失败'
    except Exception as e:
        results['SHA-256'] = str(e)

    try:
        from hmac_sha256 import hmac_sha256 as _hmac
        test_key = b"test_key_16bytes"
        test_msg = b"test_message"
        h = _hmac(test_key, test_msg)
        results['HMAC-SHA256'] = '通过' if len(h) == 32 else '失败'
    except Exception as e:
        results['HMAC-SHA256'] = str(e)

    try:
        from aes import aes_encrypt, aes_decrypt
        test_key = b"0123456789abcdef"
        test_iv = b"abcdef0123456789"
        test_pt = b"Hello AES-128-CBC"
        ct, iv = aes_encrypt(test_pt, test_key, mode='cbc', iv=test_iv)
        dt = aes_decrypt(ct, test_key, mode='cbc', iv=iv)
        results['AES-128-CBC'] = '通过' if dt == test_pt else '失败'
    except Exception as e:
        results['AES-128-CBC'] = str(e)

    try:
        from rsa import generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_sign, rsa_verify
        pub, priv = generate_keypair(1024)
        test_data = b"RSA_test_data"
        enc = rsa_encrypt_bytes(test_data, pub)
        dec = rsa_decrypt_bytes(enc, priv)
        sig = rsa_sign(test_data, priv)
        ver = rsa_verify(test_data, sig, pub)
        results['RSA'] = '通过' if dec == test_data and ver else '失败'
    except Exception as e:
        results['RSA'] = str(e)

    try:
        from dh import DHPeer
        alice = DHPeer()
        bob = DHPeer()
        alice.compute_shared_secret(bob.get_public_key())
        bob.compute_shared_secret(alice.get_public_key())
        results['DH'] = '通过' if alice.get_session_key() == bob.get_session_key() else '失败'
    except Exception as e:
        results['DH'] = str(e)

    return jsonify(results)


# ==================== Main ====================

if __name__ == '__main__':
    print(f"  Network Security Transmission Demo System v{APP_VERSION}")
    print(f"  Mode: {MODE}")
    print(f"  Listen Port: {LISTEN_PORT}")
    print(f"  Flask Port: {FLASK_PORT}")

    # 生成 RSA 密钥（1024位可能需要几秒）
    print("  正在生成 RSA 密钥...")
    try:
        get_rsa_keys()
        print("  RSA 密钥生成完成")
    except Exception as e:
        print(f"  RSA 密钥生成失败: {e}")
        import traceback
        traceback.print_exc()

    # 启动协商服务器（仅接收端需要监听，发送端主动连接对方）
    if MODE == 'receiver':
        print("  正在启动协商服务器...")
        try:
            start_negotiate_server()
            print("  协商服务器启动完成")
        except Exception as e:
            print(f"  协商服务器启动失败: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("  发送端模式，跳过协商服务器启动（主动连接对方）")

    # 启动 Flask
    print(f"  正在启动 Flask 服务 ({FLASK_HOST}:{FLASK_PORT})...")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, threaded=True)
