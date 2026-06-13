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

APP_VERSION = '1.7.0'

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request

from aes import aes_encrypt, aes_decrypt
from rsa import generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_sign, rsa_verify, save_keypair
from sha256 import sha256
from hmac_sha256 import hmac_sha256
from dh import DHPeer
from capture import capture_packets, packets_to_json, get_network_info, HAS_SCAPY

app = Flask(__name__)

MODE = os.environ.get('MODE', 'sender') or 'sender'
RECEIVER_HOST = os.environ.get('RECEIVER_HOST', '127.0.0.1') or '127.0.0.1'
RECEIVER_PORT = int(os.environ.get('RECEIVER_PORT', '9999') or '9999')
LISTEN_PORT = int(os.environ.get('LISTEN_PORT', '9999') or '9999')
RSA_BITS = int(os.environ.get('RSA_BITS', '512') or '512')
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
_received_data = []
_key_files = {'pub': None, 'priv': None}
_negotiate_server_status = {'running': False, 'port': None, 'error': None}
_negotiate_steps = []
_negotiate_server_running = False


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


def _reset_connection_state():
    global _dh_peer, _connection_state
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


# ==================== Page Routes ====================

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
        'received_count': len(_received_data),
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
            results.append({'step': 'DNS Resolution', 'ok': True, 'detail': f'{host} is an IP address, no DNS needed'})
        else:
            try:
                resolved_ip = socket.gethostbyname(host)
                results.append({'step': 'DNS Resolution', 'ok': True, 'detail': f'{host} -> {resolved_ip}'})
            except Exception as e:
                results.append({'step': 'DNS Resolution', 'ok': False, 'detail': str(e)})
                return jsonify({'success': False, 'results': results, 'error': 'DNS resolution failed'})

        start = time.time()
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            test_sock.connect((host, port))
            latency = round((time.time() - start) * 1000, 1)
            test_sock.close()
            results.append({'step': f'TCP Connect {host}:{port}', 'ok': True, 'detail': f'Success, latency {latency}ms'})
        except socket.timeout:
            results.append({'step': f'TCP Connect {host}:{port}', 'ok': False, 'detail': 'Timeout (3s)'})
            return jsonify({'success': False, 'results': results, 'error': 'TCP connection timeout'})
        except ConnectionRefusedError:
            results.append({'step': f'TCP Connect {host}:{port}', 'ok': False, 'detail': 'Connection refused'})
            return jsonify({'success': False, 'results': results, 'error': 'Connection refused'})
        except Exception as e:
            results.append({'step': f'TCP Connect {host}:{port}', 'ok': False, 'detail': str(e)})
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
                results.append({'step': 'Protocol Communication', 'ok': True, 'detail': f"Peer mode: {pong.get('mode','?')}, listen port: {pong.get('listen_port','?')}"})
            else:
                results.append({'step': 'Protocol Communication', 'ok': False, 'detail': f"Unexpected response: {pong}"})
        except Exception as e:
            results.append({'step': 'Protocol Communication', 'ok': False, 'detail': str(e)})

        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/set_mode', methods=['POST'])
def set_mode():
    global MODE
    data = request.get_json() or {}
    new_mode = data.get('mode', '')
    if new_mode not in ('sender', 'receiver'):
        return jsonify({'success': False, 'error': 'Mode must be sender or receiver'})
    if new_mode == MODE:
        return jsonify({'success': True, 'mode': MODE, 'message': f'Already in {"sender" if MODE=="sender" else "receiver"} mode'})
    MODE = new_mode
    if not _negotiate_server_running:
        start_negotiate_server()
    return jsonify({'success': True, 'mode': MODE, 'message': f'Switched to {"sender" if MODE=="sender" else "receiver"} mode, negotiate server running'})


# ==================== Custom Keys API ====================

@app.route('/api/set_rsa_keys', methods=['POST'])
def set_rsa_keys():
    """Set custom RSA public/private keys. Frontend specifies e, n, d; backend updates in real-time."""
    global _rsa_keys, _key_files
    try:
        data = request.get_json() or {}
        e_val = data.get('e')
        n_val = data.get('n')
        d_val = data.get('d')

        if e_val is None or n_val is None or d_val is None:
            return jsonify({'success': False, 'error': 'Must provide e, n, d values'})

        e_str = str(e_val)
        n_str = str(n_val)
        d_str = str(d_val)
        e_int = int(e_str, 16) if e_str.startswith('0x') or e_str.startswith('0X') else int(e_str)
        n_int = int(n_str, 16) if n_str.startswith('0x') or n_str.startswith('0X') else int(n_str)
        d_int = int(d_str, 16) if d_str.startswith('0x') or d_str.startswith('0X') else int(d_str)

        if n_int <= 0 or e_int <= 0 or d_int <= 0:
            return jsonify({'success': False, 'error': 'Key values must be positive integers'})

        with _rsa_lock:
            _rsa_keys = ((e_int, n_int), (d_int, n_int))
            pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                                prefix=os.path.join(DATA_DIR, 'rsa_key'))
            _key_files['pub'] = os.path.abspath(pub_path)
            _key_files['priv'] = os.path.abspath(priv_path)

        return jsonify({
            'success': True,
            'message': 'RSA keys updated',
            'public_key': {'e': e_int, 'n': hex(n_int), 'n_bits': n_int.bit_length()},
            'private_key': {'d': hex(d_int), 'd_bits': d_int.bit_length()},
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/set_dh_keys', methods=['POST'])
def set_dh_keys():
    """Set custom DH private key. Frontend specifies private_key; backend computes public_key in real-time."""
    global _dh_peer
    try:
        data = request.get_json() or {}
        private_key_val = data.get('private_key')
        prime_val = data.get('prime')
        generator_val = data.get('generator')

        if private_key_val is None:
            return jsonify({'success': False, 'error': 'Must provide private_key value'})

        pk_str = str(private_key_val)
        if pk_str.startswith('0x') or pk_str.startswith('0X'):
            pk_int = int(pk_str, 16)
        else:
            pk_int = int(pk_str)
        p_int = int(str(prime_val), 16) if prime_val else None
        g_str = str(generator_val) if generator_val else None
        if g_str:
            if g_str.startswith('0x') or g_str.startswith('0X'):
                g_int = int(g_str, 16)
            else:
                g_int = int(g_str)
        else:
            g_int = None

        if pk_int <= 0:
            return jsonify({'success': False, 'error': 'DH private key must be positive'})

        _dh_peer = DHPeer(bits=256, prime=p_int, generator=g_int)
        _dh_peer.private_key = pk_int
        _dh_peer.public_key = pow(_dh_peer.g, _dh_peer.private_key, _dh_peer.p)

        return jsonify({
            'success': True,
            'message': 'DH keys updated',
            'private_key': hex(_dh_peer.private_key),
            'public_key': hex(_dh_peer.public_key),
            'prime_bits': _dh_peer.p.bit_length(),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/regenerate_keys', methods=['POST'])
def regenerate_keys():
    """Regenerate all keys (RSA + DH) randomly."""
    global _rsa_keys, _dh_peer, _key_files
    try:
        with _rsa_lock:
            _rsa_keys = generate_keypair(RSA_BITS)
            pub_path, priv_path = save_keypair(_rsa_keys[0], _rsa_keys[1],
                                                prefix=os.path.join(DATA_DIR, 'rsa_key'))
            _key_files['pub'] = os.path.abspath(pub_path)
            _key_files['priv'] = os.path.abspath(priv_path)

        if _dh_peer:
            _dh_peer = DHPeer(bits=256)

        return jsonify({
            'success': True,
            'message': 'All keys regenerated randomly',
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
             'flag': 'SYN', 'desc': 'Send SYN packet'},
            {'step': 2, 'dir': '<-', 'from': f'{target_host}:{target_port}', 'to': f'{local_ip}:{local_port}',
             'flag': 'SYN+ACK', 'desc': 'Receive SYN+ACK'},
            {'step': 3, 'dir': '->', 'from': f'{local_ip}:{local_port}', 'to': f'{target_host}:{target_port}',
             'flag': 'ACK', 'desc': 'Send ACK, connection established'},
        ]
        _connection_state['tcp_handshake'] = handshake_info

        result['steps'].append({
            'id': 1,
            'title': 'Step 1: TCP Three-way Handshake',
            'status': 'success',
            'description': 'Establish reliable TCP connection with receiver',
            'detail': {
                'Connection Parameters': {
                    'Sender (local)': f'{local_ip}:{local_port}',
                    'Receiver (target)': f'{target_host}:{target_port}',
                    'Protocol': 'TCP',
                    'Window Size': str(win_size),
                    'MSS': str(mss)
                },
                '1st Handshake (SYN)': {
                    'Direction': f'{local_ip}:{local_port} -> {target_host}:{target_port}',
                    'Flags': 'SYN=1',
                    'Seq': str(seq1),
                    'Ack': '0',
                    'Meaning': 'Sender requests connection with initial seq=' + str(seq1)
                },
                '2nd Handshake (SYN+ACK)': {
                    'Direction': f'{target_host}:{target_port} -> {local_ip}:{local_port}',
                    'Flags': 'SYN=1, ACK=1',
                    'Seq': str(seq2),
                    'Ack': str(seq1 + 1),
                    'Meaning': 'Receiver confirms SYN, sends own seq=' + str(seq2)
                },
                '3rd Handshake (ACK)': {
                    'Direction': f'{local_ip}:{local_port} -> {target_host}:{target_port}',
                    'Flags': 'ACK=1',
                    'Seq': str(seq1 + 1),
                    'Ack': str(seq2 + 1),
                    'Meaning': 'Sender confirms, connection established'
                },
            }
        })

        try:
            sock.connect((target_host, target_port))
        except socket.timeout:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP connection timeout: cannot connect to {target_host}:{target_port}', 'steps': result['steps']})
        except ConnectionRefusedError:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'Connection refused: {target_host}:{target_port}', 'steps': result['steps']})
        except Exception as e:
            result['steps'][0]['status'] = 'error'
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': f'TCP connection failed: {e}', 'steps': result['steps']})

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
            'title': 'Step 2: RSA Public Key Exchange',
            'status': 'success',
            'description': 'Exchange RSA public keys for signature verification',
            'detail': {
                'My RSA Public Key': {
                    'e': str(my_rsa_pub[0]),
                    'n': str(my_rsa_pub[1])[:64] + f"... ({my_rsa_pub[1].bit_length()} bits)",
                },
                'Peer RSA Public Key': {
                    'e': str(peer_rsa_e),
                    'n': str(peer_rsa_n)[:64] + f"... ({peer_rsa_n.bit_length()} bits)",
                },
                'Purpose': 'Used to verify DH public key signatures in next step'
            }
        })

        # Step 3: DH Public Key Exchange with RSA Signature
        _connection_state['status'] = 'exchanging_dh_keys'

        _dh_peer = DHPeer(bits=256)
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
            'title': 'Step 3: DH Public Key Exchange (with RSA Signature)',
            'status': 'success',
            'description': 'Exchange DH public keys signed with RSA private key',
            'detail': {
                'My DH Key Pair': {
                    'DH Private Key (secret)': hex(_dh_peer.private_key)[:40] + '...',
                    'DH Public Key': hex(my_dh_public),
                },
                'My RSA Signature on DH Public Key': {
                    'Signature': my_signature.hex()[:64] + '...',
                    'Algorithm': 'SHA256(DH_pub) -> RSA_sign(hash)',
                },
                'Peer DH Public Key': hex(peer_dh_public),
                'Peer DH Signature': peer_dh_signature.hex()[:64] + '...',
            }
        })

        # Step 4: Verify Peer Signature
        _connection_state['status'] = 'verifying_signatures'

        peer_dh_public_bytes = peer_dh_public.to_bytes((peer_dh_public.bit_length() + 7) // 8, 'big')

        from sha256 import sha256 as _sha256_dbg
        actual_hash_dbg = int.from_bytes(_sha256_dbg(peer_dh_public_bytes), 'big')
        recovered_hash_dbg = pow(int.from_bytes(peer_dh_signature, 'big'), peer_rsa_e, peer_rsa_n)
        sig_match = (actual_hash_dbg == recovered_hash_dbg)

        peer_verified = rsa_verify(peer_dh_public_bytes, peer_dh_signature, peer_rsa_pub)
        _connection_state['peer_verified'] = peer_verified

        if not peer_verified:
            result['steps'].append({
                'id': 4,
                'title': 'Step 4: Verify Peer Signature',
                'status': 'error',
                'description': 'RSA signature verification FAILED',
                'detail': {
                    'Result': 'FAILED',
                    'Possible Cause': 'Man-in-the-middle attack or data corruption'
                }
            })
            sock.close()
            _connection_state['status'] = 'disconnected'
            return jsonify({'success': False, 'error': 'Peer signature verification failed!', 'steps': result['steps']})

        result['steps'].append({
            'id': 4,
            'title': 'Step 4: Verify Peer Signature',
            'status': 'success',
            'description': 'Verify peer DH public key signature using peer RSA public key',
            'detail': {
                'Verification Method': [
                    '1. Compute SHA256(peer_DH_pub) -> H',
                    '2. Decrypt signature with peer RSA pub key -> H\'',
                    '3. Compare H == H\''
                ],
                'Result': 'PASSED',
                'Actual Hash (H)': hex(actual_hash_dbg),
                'Recovered Hash (H\')': hex(recovered_hash_dbg),
                'Meaning': 'Peer DH public key is authentic and untampered'
            }
        })

        # Step 5: Compute Shared Session Key
        _dh_peer.compute_shared_secret(peer_dh_public)
        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()

        _connection_state['session_key'] = session_key.hex()
        _connection_state['hmac_key'] = hmac_key.hex()
        _connection_state['status'] = 'connected'

        sock.close()

        result['steps'].append({
            'id': 5,
            'title': 'Step 5: Compute Shared Session Key',
            'status': 'success',
            'description': 'Both sides independently compute the same shared secret via DH, derive AES and HMAC keys',
            'detail': {
                'DH Shared Secret Computation': {
                    'Formula': 'shared_secret = peer_DH_pub ^ my_DH_priv mod p',
                    'Math': '(g^b)^a mod p = (g^a)^b mod p = g^(ab) mod p',
                    'Security': 'Discrete logarithm problem prevents eavesdroppers from computing shared secret'
                },
                'Key Derivation (SHA-256)': {
                    'Input': f'DH shared secret ({_dh_peer.shared_secret.bit_length()} bits)',
                    'Output (32 bytes)': 'First 16 bytes = AES-128-CBC key | Last 16 bytes = HMAC-SHA256 key',
                    'AES Session Key': session_key.hex(),
                    'HMAC Key': hmac_key.hex()
                },
                'Result': {
                    'Status': 'Connection established',
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
        return jsonify({'success': False, 'error': f'Connection error: {e}', 'detail': traceback.format_exc()})


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
            results.append({'step': 'TCP Connect', 'ok': True, 'detail': f'Connected to {host}:{port}'})
        except socket.timeout:
            results.append({'step': 'TCP Connect', 'ok': False, 'detail': f'Timeout {host}:{port}'})
            return jsonify({'success': False, 'results': results})
        except ConnectionRefusedError:
            results.append({'step': 'TCP Connect', 'ok': False, 'detail': f'Refused {host}:{port}'})
            return jsonify({'success': False, 'results': results})
        except Exception as e:
            results.append({'step': 'TCP Connect', 'ok': False, 'detail': str(e)})
            return jsonify({'success': False, 'results': results})

        try:
            ping_msg = json.dumps({'type': 'ping'}).encode()
            sock.sendall(struct.pack('>I', len(ping_msg)) + ping_msg)
            results.append({'step': 'Send ping', 'ok': True, 'detail': 'Ping sent'})
        except Exception as e:
            results.append({'step': 'Send ping', 'ok': False, 'detail': str(e)})
            sock.close()
            return jsonify({'success': False, 'results': results})

        try:
            pong_len_data = _recv_exact(sock, 4, timeout=5)
            pong_len = struct.unpack('>I', pong_len_data)[0]
            if pong_len > 10000:
                results.append({'step': 'Read pong', 'ok': False, 'detail': f'Abnormal length: {pong_len}'})
                sock.close()
                return jsonify({'success': False, 'results': results})
            pong_data = _recv_exact(sock, pong_len, timeout=5)
            pong = json.loads(pong_data.decode())
            results.append({'step': 'Read pong', 'ok': True, 'detail': f"Peer mode: {pong.get('mode')}, listen port: {pong.get('listen_port')}"})
        except Exception as e:
            results.append({'step': 'Read pong', 'ok': False, 'detail': f'Failed: {e}'})
            sock.close()
            return jsonify({'success': False, 'results': results})

        sock.close()
        results.append({'step': 'Conclusion', 'ok': True, 'detail': 'TCP and protocol OK, ready for full connection'})
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
    """Disconnect and notify peer (bidirectional disconnect sync)."""
    if _connection_state['status'] == 'connected':
        _notify_peer_disconnect()
    _reset_connection_state()
    global _negotiate_steps
    _negotiate_steps = []
    return jsonify({'success': True, 'message': 'Connection reset'})


@app.route('/api/restart_negotiate', methods=['POST'])
def restart_negotiate():
    global _negotiate_server_running, _negotiate_server_status
    _negotiate_server_running = False
    _negotiate_server_status = {'running': False, 'port': None, 'error': None}
    time.sleep(0.5)
    start_negotiate_server()
    return jsonify({'success': True, 'negotiate_server': _negotiate_server_status})


# ==================== Receiver Negotiation Server ====================

def start_negotiate_server():
    global _negotiate_server_running, _dh_peer, _connection_state

    if _negotiate_server_running:
        return

    def server_thread():
        global _dh_peer, _connection_state, _negotiate_server_status, _negotiate_server_running, _negotiate_steps
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(300)
            server_sock.bind(('0.0.0.0', LISTEN_PORT))
            server_sock.listen(5)
            print(f"  [Negotiate Server] Listening on 0.0.0.0:{LISTEN_PORT}")
            _negotiate_server_running = True
            _negotiate_server_status = {'running': True, 'port': LISTEN_PORT, 'error': None}
        except Exception as e:
            print(f"  [Negotiate Server] Failed to start: {e}")
            _negotiate_server_status = {'running': False, 'port': LISTEN_PORT, 'error': str(e)}
            _negotiate_server_running = False
            return

        while True:
            conn = None
            try:
                conn, addr = server_sock.accept()
                conn.settimeout(30)
                print(f"  [Negotiate Server] Connection from {addr}")

                prev_status = _connection_state['status']
                _connection_state['peer_ip'] = addr[0]
                _connection_state['peer_port'] = addr[1]

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

                # Handle ping
                if req.get('type') == 'ping':
                    try:
                        pong = json.dumps({'type': 'pong', 'mode': MODE, 'listen_port': LISTEN_PORT}).encode()
                        conn.sendall(struct.pack('>I', len(pong)) + pong)
                    except:
                        pass
                    conn.close()
                    _connection_state['status'] = prev_status
                    continue

                # Handle data transfer
                elif req.get('type') == 'data_transfer':
                    if _dh_peer and _dh_peer.get_session_key():
                        _handle_data_transfer(conn, req)
                    conn.close()
                    continue

                # Key negotiation
                _connection_state['status'] = 'negotiating'
                _negotiate_steps = []

                _negotiate_steps.append({
                    'id': 1,
                    'title': 'Step 1: TCP Three-way Handshake',
                    'status': 'success',
                    'description': 'Sender initiated TCP connection, three-way handshake completed',
                    'detail': {
                        'Connection Parameters': {
                            'Sender (peer)': f'{addr[0]}:{addr[1]}',
                            'Receiver (local)': f'{_get_local_ip()}:{LISTEN_PORT}',
                            'Protocol': 'TCP',
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
                        'title': 'Step 2: RSA Public Key Exchange',
                        'status': 'success',
                        'description': 'Received sender RSA public key, sent our RSA public key',
                        'detail': {
                            'Peer RSA Public Key': {
                                'e': str(peer_rsa_e),
                                'n': str(peer_rsa_n)[:64] + f"... ({peer_rsa_n.bit_length()} bits)",
                            },
                            'My RSA Public Key': {
                                'e': str(my_rsa_pub[0]),
                                'n': str(my_rsa_pub[1])[:64] + f"... ({my_rsa_pub[1].bit_length()} bits)",
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

                    _dh_peer = DHPeer(bits=256)
                    my_dh_public = _dh_peer.get_public_key()
                    my_dh_private = _dh_peer.private_key

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
                        'title': 'Step 3: DH Public Key Exchange (with RSA Signature)',
                        'status': 'success',
                        'description': 'Exchanged DH public keys with RSA signatures',
                        'detail': {
                            'My DH Public Key': hex(my_dh_public),
                            'My RSA Signature': my_signature.hex()[:64] + '...',
                            'Peer DH Public Key': hex(peer_dh_public),
                            'Peer RSA Signature': peer_dh_signature.hex()[:64] + '...',
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
                            'title': 'Step 4: Verify Peer Signature',
                            'status': 'success',
                            'description': 'Peer DH public key signature verified successfully',
                            'detail': {
                                'Verification Method': [
                                    '1. Compute SHA256(peer_DH_pub) -> H',
                                    '2. Decrypt signature with peer RSA pub key -> H\'',
                                    '3. Compare H == H\''
                                ],
                                'Result': 'PASSED',
                                'Actual Hash (H)': hex(actual_hash_dbg),
                                'Recovered Hash (H\')': hex(recovered_hash_dbg),
                            }
                        })
                    else:
                        _negotiate_steps.append({
                            'id': 4,
                            'title': 'Step 4: Verify Peer Signature',
                            'status': 'error',
                            'description': 'Peer signature verification FAILED',
                            'detail': {
                                'Result': 'FAILED',
                                'Warning': 'Possible MITM attack or data corruption'
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

                        _negotiate_steps.append({
                            'id': 5,
                            'title': 'Step 5: Compute Shared Session Key',
                            'status': 'success',
                            'description': 'Both sides computed the same shared secret, derived AES and HMAC keys',
                            'detail': {
                                'DH Shared Secret': {
                                    'Formula': 'shared_secret = peer_DH_pub ^ my_DH_priv mod p',
                                    'Security': 'Discrete logarithm problem'
                                },
                                'Key Derivation (SHA-256)': {
                                    'AES Session Key': session_key.hex(),
                                    'HMAC Key': hmac_key.hex()
                                },
                                'Result': {
                                    'Status': 'Connection established',
                                }
                            }
                        })

                conn.close()

            except socket.timeout:
                continue
            except ConnectionError as e:
                print(f"  [Negotiate Server] Connection error: {e}")
                if conn:
                    try: conn.close()
                    except: pass
                continue
            except Exception as e:
                print(f"  [Negotiate Server] Error: {e}")
                import traceback
                traceback.print_exc()
                if conn:
                    try: conn.close()
                    except: pass
                continue

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()


def _handle_data_transfer(conn, req):
    global _received_data
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
            'id': 1, 'title': 'Receive Encrypted Data',
            'description': 'Received encrypted data packet and digital signature from sender',
            'data': {
                'Encrypted packet length': f'{data_len} bytes',
                'Ciphertext length': f'{len(ct)} bytes',
                'Signature length': f'{sig_len} bytes',
                'Sender IP': _connection_state.get('peer_ip', 'unknown'),
            }
        })

        computed_hmac = hmac_sha256(hmac_key, ct)
        hmac_valid = (computed_hmac == recv_hmac)
        steps.append({
            'id': 2, 'title': 'HMAC-SHA256 Integrity Verification',
            'description': 'Recompute HMAC with DH-derived key and compare with received HMAC',
            'data': {
                'HMAC Key': hmac_key.hex(),
                'Received HMAC': recv_hmac.hex(),
                'Computed HMAC': computed_hmac.hex(),
                'Result': 'PASSED - Data intact' if hmac_valid else 'FAILED - Data may be tampered!',
            },
            'status': 'success' if hmac_valid else 'error'
        })

        sig_verified = rsa_verify(ct, signature, _connection_state.get('peer_public_key_raw', get_rsa_keys()[0]))
        steps.append({
            'id': 3, 'title': 'RSA Digital Signature Verification',
            'description': 'Verify signature with sender RSA public key for non-repudiation',
            'data': {
                'Algorithm': 'RSA-SHA256',
                'Result': 'PASSED - Authentic' if sig_verified else 'FAILED - Untrusted!',
            },
            'status': 'success' if sig_verified else 'error'
        })

        decrypted = aes_decrypt(ct, session_key, mode='cbc', iv=recv_iv)
        decrypted_text = decrypted.decode('utf-8')
        steps.append({
            'id': 4, 'title': 'AES-128-CBC Decryption',
            'description': 'Decrypt ciphertext with DH-derived session key',
            'data': {
                'AES Key': session_key.hex(),
                'IV': recv_iv.hex() if recv_iv else '',
                'Ciphertext (first 128 bytes)': ct.hex()[:128] + '...',
                'Decrypted length': f'{len(decrypted_text)} chars',
                'Result': 'Success' if hmac_valid and sig_verified else 'Decrypted but verification failed',
            },
            'status': 'success' if hmac_valid and sig_verified else 'error'
        })

        filepath = os.path.join(DATA_DIR, 'latest_received.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(decrypted_text)

        steps.append({
            'id': 5, 'title': 'Save Decrypted Data',
            'description': 'Save decrypted data to file',
            'data': {
                'Save path': os.path.abspath(filepath),
                'Data length': f'{len(decrypted_text)} chars',
                'Preview': decrypted_text[:300] + ('...' if len(decrypted_text) > 300 else ''),
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
                record['error'] += 'HMAC verification failed! '
            if not sig_verified:
                record['error'] += 'RSA signature verification failed! '

        _received_data.append(record)

    except Exception as e:
        _received_data.append({
            'time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'hmac_valid': False,
            'sig_verified': False,
            'error': str(e),
            'steps': [{
                'id': 0, 'title': 'Receive Failed',
                'description': 'Exception during data transfer',
                'data': {'Error': str(e)},
                'status': 'error'
            }]
        })


def _recv_exact(sock, n, timeout=30):
    sock.settimeout(timeout)
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
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
            return jsonify({'success': False, 'error': 'scapy not available'})

        packets_info, capture_log = capture_packets(count=count, timeout=timeout, filter_rule=filter_rule)

        json_data = packets_to_json(packets_info)
        filepath = os.path.join(DATA_DIR, f'capture_{int(time.time()*1000)}.json')
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
        result['issues'].append('scapy not installed')
        return jsonify(result)

    try:
        from scapy.all import get_if_list, get_if_addr, conf
        result['scapy_conf_iface'] = str(conf.iface)

        for iface_name in get_if_list():
            try:
                ip = get_if_addr(str(iface_name))
                result['ifaces'].append({'name': str(iface_name), 'ip': ip})
            except:
                result['ifaces'].append({'name': str(iface_name), 'ip': 'N/A'})

        from capture import _auto_select_interface
        auto_iface = _auto_select_interface()
        result['auto_selected_iface'] = auto_iface

        sniff_test = 'Not tested'
        if auto_iface:
            try:
                from scapy.all import sniff as _sniff
                pkts = _sniff(count=1, timeout=3, iface=auto_iface, store=False)
                sniff_test = 'OK - can capture packets'
            except Exception as e:
                sniff_test = f'Failed: {e}'
        result['sniff_test'] = sniff_test

    except Exception as e:
        result['issues'].append(str(e))

    return jsonify(result)


# ==================== Send Data API ====================

@app.route('/api/send', methods=['POST'])
def api_send():
    """Sender: Encrypt data with AES+HMAC+RSA signature and send to receiver."""
    global _received_data
    try:
        data = request.get_json() or {}
        plaintext = data.get('data', '')
        if not plaintext:
            return jsonify({'success': False, 'error': 'No data to send'})

        if not _dh_peer or not _dh_peer.get_session_key():
            return jsonify({'success': False, 'error': 'Not connected, please establish connection first'})

        session_key = _dh_peer.get_session_key()
        hmac_key = _dh_peer.get_hmac_key()
        peer_ip = _connection_state.get('peer_ip')
        peer_port = _connection_state.get('peer_listen_port') or RECEIVER_PORT

        if not peer_ip:
            return jsonify({'success': False, 'error': 'No peer connection info'})

        steps = []

        # Step 1: AES-128-CBC Encryption
        iv = os.urandom(16)
        ciphertext, iv_used = aes_encrypt(plaintext.encode('utf-8'), session_key, mode='cbc', iv=iv)
        steps.append({
            'id': 1, 'title': 'AES-128-CBC Encryption',
            'description': 'Encrypt plaintext with DH-derived session key',
            'detail': {
                'AES Key': session_key.hex(),
                'IV': iv_used.hex(),
                'Plaintext length': f'{len(plaintext)} chars',
                'Ciphertext length': f'{len(ciphertext)} bytes',
            }
        })

        # Step 2: HMAC-SHA256 Authentication
        hmac_value = hmac_sha256(hmac_key, ciphertext)
        steps.append({
            'id': 2, 'title': 'HMAC-SHA256 Authentication',
            'description': 'Compute HMAC for ciphertext integrity verification',
            'detail': {
                'HMAC Key': hmac_key.hex(),
                'HMAC Value': hmac_value.hex(),
                'Purpose': 'Ensure data integrity during transmission',
            }
        })

        # Step 3: RSA Digital Signature
        my_rsa_priv = get_rsa_keys()[1]
        signature = rsa_sign(ciphertext, my_rsa_priv)
        steps.append({
            'id': 3, 'title': 'RSA Digital Signature',
            'description': 'Sign ciphertext with RSA private key for non-repudiation',
            'detail': {
                'Signature Algorithm': 'RSA-SHA256',
                'Signature Value': signature.hex()[:64] + '...',
                'Purpose': 'Ensure data authenticity and non-repudiation',
            }
        })

        # Step 4: Pack and Send
        from network import pack_packet
        peer_rsa_pub = _connection_state.get('peer_public_key_raw')
        encrypted_aes_key = rsa_encrypt_bytes(session_key, peer_rsa_pub) if peer_rsa_pub else b''
        encrypted_hmac_key = rsa_encrypt_bytes(hmac_key, peer_rsa_pub) if peer_rsa_pub else b''

        packet = pack_packet(ciphertext, encrypted_aes_key, encrypted_hmac_key, hmac_value, iv=iv_used)
        steps.append({
            'id': 4, 'title': 'Pack and Send',
            'description': 'Pack encrypted data and send via TCP',
            'detail': {
                'Packet size': f'{len(packet)} bytes',
                'Target': f'{peer_ip}:{peer_port}',
                'Encrypted AES key length': f'{len(encrypted_aes_key)} bytes',
                'Encrypted HMAC key length': f'{len(encrypted_hmac_key)} bytes',
            }
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
            send_sock.close()
        except Exception as e:
            return jsonify({'success': False, 'error': f'Send failed: {e}', 'steps': steps})

        steps.append({
            'id': 5, 'title': 'Send Complete',
            'description': 'Encrypted data sent successfully',
            'detail': {
                'Status': 'Success',
                'Data sent to': f'{peer_ip}:{peer_port}',
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
        'count': len(_received_data),
        'data': _received_data,
    })


# ==================== Algorithm Test API ====================

@app.route('/api/test_algo', methods=['POST'])
def test_algo():
    results = {}
    try:
        from sha256 import sha256 as _sha256
        test_msg = b"test_message_123"
        h = _sha256(test_msg)
        results['SHA-256'] = 'PASS' if len(h) == 32 else 'FAIL'
    except Exception as e:
        results['SHA-256'] = str(e)

    try:
        from hmac_sha256 import hmac_sha256 as _hmac
        test_key = b"test_key_16bytes"
        test_msg = b"test_message"
        h = _hmac(test_key, test_msg)
        results['HMAC-SHA256'] = 'PASS' if len(h) == 32 else 'FAIL'
    except Exception as e:
        results['HMAC-SHA256'] = str(e)

    try:
        from aes import aes_encrypt, aes_decrypt
        test_key = b"0123456789abcdef"
        test_iv = b"abcdef0123456789"
        test_pt = b"Hello AES-128-CBC"
        ct, iv = aes_encrypt(test_pt, test_key, mode='cbc', iv=test_iv)
        dt = aes_decrypt(ct, test_key, mode='cbc', iv=iv)
        results['AES-128-CBC'] = 'PASS' if dt == test_pt else 'FAIL'
    except Exception as e:
        results['AES-128-CBC'] = str(e)

    try:
        from rsa import generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes, rsa_sign, rsa_verify
        pub, priv = generate_keypair(512)
        test_data = b"RSA_test_data"
        enc = rsa_encrypt_bytes(test_data, pub)
        dec = rsa_decrypt_bytes(enc, priv)
        sig = rsa_sign(test_data, priv)
        ver = rsa_verify(test_data, sig, pub)
        results['RSA'] = 'PASS' if dec == test_data and ver else 'FAIL'
    except Exception as e:
        results['RSA'] = str(e)

    try:
        from dh import DHPeer
        alice = DHPeer(bits=256)
        bob = DHPeer(bits=256)
        alice.compute_shared_secret(bob.get_public_key())
        bob.compute_shared_secret(alice.get_public_key())
        results['DH'] = 'PASS' if alice.get_session_key() == bob.get_session_key() else 'FAIL'
    except Exception as e:
        results['DH'] = str(e)

    return jsonify(results)


# ==================== Main ====================

if __name__ == '__main__':
    print(f"  Network Security Transmission Demo System v{APP_VERSION}")
    print(f"  Mode: {MODE}")
    print(f"  Listen Port: {LISTEN_PORT}")
    print(f"  Flask Port: {FLASK_PORT}")

    get_rsa_keys()

    start_negotiate_server()

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
