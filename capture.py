"""
网络数据采集模块 - 详细版
使用 scapy 抓取真实网络数据包，提取详细协议信息
包含完整的抓包过程记录：网卡选择、过滤器设置、每个包的详细解析
"""
import socket
import struct
import time
import json
import threading
import os

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, Ether, conf, get_if_addr, get_if_list
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# TCP 标志位映射
TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}

# 协议号映射
IP_PROTO = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
    41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH',
    89: 'OSPF', 132: 'SCTP'
}


def _parse_tcp_flags(flags_int):
    """解析 TCP 标志位为可读字符串"""
    flags_str = []
    flag_bits = [('CWR', 0x80), ('ECE', 0x40), ('URG', 0x20), ('ACK', 0x10),
                 ('PSH', 0x08), ('RST', 0x04), ('SYN', 0x02), ('FIN', 0x01)]
    for name, bit in flag_bits:
        if flags_int & bit:
            flags_str.append(name)
    return ','.join(flags_str) if flags_str else 'NONE'


def _get_interfaces():
    """获取可用网络接口列表"""
    if not HAS_SCAPY:
        return []
    try:
        ifaces = []
        for iface_name in get_if_list():
            try:
                ip = get_if_addr(iface_name)
                ifaces.append({'name': str(iface_name), 'ip': ip})
            except:
                ifaces.append({'name': str(iface_name), 'ip': 'N/A'})
        return ifaces
    except:
        return []


def _auto_select_interface():
    """自动选择有IP地址的网卡接口（优先选择非loopback）"""
    if not HAS_SCAPY:
        return None
    try:
        from scapy.all import get_if_list, get_if_addr, conf
        # 优先使用scapy默认接口
        default_iface = conf.iface
        if default_iface:
            try:
                ip = get_if_addr(str(default_iface))
                if ip and ip != '0.0.0.0' and not ip.startswith('127.'):
                    return str(default_iface)
            except:
                pass

        # 遍历所有接口，找有非loopback IP的
        for iface_name in get_if_list():
            try:
                ip = get_if_addr(str(iface_name))
                if ip and ip != '0.0.0.0' and not ip.startswith('127.'):
                    return str(iface_name)
            except:
                continue

        # 回退：找任何有IP的接口
        for iface_name in get_if_list():
            try:
                ip = get_if_addr(str(iface_name))
                if ip and ip != '0.0.0.0':
                    return str(iface_name)
            except:
                continue

        # 最后回退到None（让scapy自己选）
        return None
    except:
        return None


def capture_packets_scapy(count=10, timeout=15, interface=None, filter_rule="ip"):
    """
    使用 scapy 抓取网络数据包（详细版）
    返回包含抓包过程详情的结果
    """
    if not HAS_SCAPY:
        raise RuntimeError("scapy 未安装")

    packets_info = []
    capture_log = []  # 抓包过程日志

    # 记录抓包开始信息
    capture_log.append({
        'time': time.strftime("%H:%M:%S"),
        'event': 'init',
        'detail': f'初始化抓包引擎: 目标 {count} 个包, 超时 {timeout}s, 过滤规则 "{filter_rule}"'
    })

    # 获取网络接口信息
    ifaces = _get_interfaces()
    capture_log.append({
        'time': time.strftime("%H:%M:%S"),
        'event': 'interface',
        'detail': f'可用网卡接口: {len(ifaces)} 个',
        'interfaces': ifaces
    })

    # 自动选择网卡（如果未指定）
    if not interface:
        interface = _auto_select_interface()
        if interface:
            capture_log.append({
                'time': time.strftime("%H:%M:%S"),
                'event': 'select_iface',
                'detail': f'自动选择网卡: {interface}'
            })
        else:
            capture_log.append({
                'time': time.strftime("%H:%M:%S"),
                'event': 'select_iface',
                'detail': '未指定网卡，使用scapy默认接口'
            })
    else:
        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'select_iface',
            'detail': f'手动选择网卡: {interface}'
        })

    capture_log.append({
        'time': time.strftime("%H:%M:%S"),
        'event': 'start',
        'detail': f'开始抓包... (接口: {interface}, BPF过滤器: "{filter_rule}")'
    })

    start_time = time.time()

    def process_packet(pkt):
        pkt_time = time.strftime("%H:%M:%S.%f")[:-3]
        info = {
            "id": len(packets_info) + 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_precise": pkt_time,
            "length": 0,
            # 以太网层
            "src_mac": "",
            "dst_mac": "",
            "ether_type": "",
            # 网络层
            "src_ip": "",
            "dst_ip": "",
            "ip_version": "",
            "ttl": 0,
            "ip_id": 0,
            "ip_flags": "",
            "fragment_offset": 0,
            # 传输层
            "protocol": "",
            "src_port": "",
            "dst_port": "",
            # TCP 详细
            "tcp_flags": "",
            "tcp_flags_raw": 0,
            "seq_num": 0,
            "ack_num": 0,
            "window_size": 0,
            "tcp_options": "",
            # 载荷
            "payload": "",
            "payload_hex": "",
            "payload_length": 0,
            # 摘要
            "summary": ""
        }

        # 以太网层
        if Ether in pkt:
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst
            info["ether_type"] = hex(pkt[Ether].type)

        # IP 层
        if IP in pkt:
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
            info["ip_version"] = pkt[IP].version
            info["ttl"] = pkt[IP].ttl
            info["ip_id"] = pkt[IP].id
            info["length"] = len(pkt)

            # IP 标志
            ip_flags_val = pkt[IP].flags
            ip_flags_str = []
            if ip_flags_val & 0x4: ip_flags_str.append('DF')
            if ip_flags_val & 0x2: ip_flags_str.append('MF')
            info["ip_flags"] = ','.join(ip_flags_str) if ip_flags_str else 'None'
            info["fragment_offset"] = pkt[IP].frag

            # TCP 层
            if TCP in pkt:
                info["protocol"] = "TCP"
                info["src_port"] = str(pkt[TCP].sport)
                info["dst_port"] = str(pkt[TCP].dport)
                info["tcp_flags"] = _parse_tcp_flags(pkt[TCP].flags)
                info["tcp_flags_raw"] = int(pkt[TCP].flags)
                info["seq_num"] = pkt[TCP].seq
                info["ack_num"] = pkt[TCP].ack
                info["window_size"] = pkt[TCP].window

                # TCP 选项
                try:
                    opts = []
                    for opt in pkt[TCP].options:
                        if isinstance(opt, tuple) and len(opt) >= 1:
                            opts.append(str(opt[0]))
                    info["tcp_options"] = ','.join(opts) if opts else ''
                except:
                    info["tcp_options"] = ''

                # 生成摘要
                flags_desc = info["tcp_flags"]
                info["summary"] = f"TCP [{flags_desc}] {info['src_ip']}:{info['src_port']} → {info['dst_ip']}:{info['dst_port']} seq={info['seq_num']}"

                # 记录到抓包日志
                capture_log.append({
                    'time': pkt_time,
                    'event': 'packet',
                    'detail': f'TCP [{flags_desc}] {info["src_ip"]}:{info["src_port"]} → {info["dst_ip"]}:{info["dst_port"]} len={info["length"]}'
                })

            # UDP 层
            elif UDP in pkt:
                info["protocol"] = "UDP"
                info["src_port"] = str(pkt[UDP].sport)
                info["dst_port"] = str(pkt[UDP].dport)
                info["summary"] = f"UDP {info['src_ip']}:{info['src_port']} → {info['dst_ip']}:{info['dst_port']}"

                capture_log.append({
                    'time': pkt_time,
                    'event': 'packet',
                    'detail': f'UDP {info["src_ip"]}:{info["src_port"]} → {info["dst_ip"]}:{info["dst_port"]} len={info["length"]}'
                })

            # ICMP 层
            elif ICMP in pkt:
                info["protocol"] = "ICMP"
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                icmp_types = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
                type_name = icmp_types.get(icmp_type, f'Type{icmp_type}')
                info["summary"] = f"ICMP {type_name} ({icmp_type}/{icmp_code}) {info['src_ip']} → {info['dst_ip']}"

                capture_log.append({
                    'time': pkt_time,
                    'event': 'packet',
                    'detail': f'ICMP {type_name} {info["src_ip"]} → {info["dst_ip"]}'
                })
            else:
                info["protocol"] = IP_PROTO.get(pkt[IP].proto, str(pkt[IP].proto))
                info["summary"] = f"{info['protocol']} {info['src_ip']} → {info['dst_ip']}"

                capture_log.append({
                    'time': pkt_time,
                    'event': 'packet',
                    'detail': f'{info["protocol"]} {info["src_ip"]} → {info["dst_ip"]}'
                })

            # 载荷
            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                info["payload_length"] = len(raw_data)
                info["payload_hex"] = raw_data.hex()[:500]
                try:
                    info["payload"] = raw_data.decode('utf-8', errors='replace')[:300]
                except:
                    info["payload"] = ""

        # ARP 层
        elif ARP in pkt:
            info["protocol"] = "ARP"
            info["src_ip"] = pkt[ARP].psrc
            info["dst_ip"] = pkt[ARP].pdst
            info["src_mac"] = pkt[ARP].hwsrc
            info["dst_mac"] = pkt[ARP].hwdst
            arp_op = {1: 'Request', 2: 'Reply'}.get(pkt[ARP].op, f'op{pkt[ARP].op}')
            info["summary"] = f"ARP {arp_op}: {pkt[ARP].psrc}({pkt[ARP].hwsrc}) → {pkt[ARP].pdst}({pkt[ARP].hwdst})"
            info["length"] = len(pkt)

            capture_log.append({
                'time': pkt_time,
                'event': 'packet',
                'detail': f'ARP {arp_op}: {pkt[ARP].psrc} → {pkt[ARP].pdst}'
            })

        packets_info.append(info)

    # 执行抓包
    kwargs = {
        'prn': process_packet,
        'count': count,
        'timeout': timeout,
        'store': False
    }
    if interface:
        kwargs['iface'] = interface
    if filter_rule:
        kwargs['filter'] = filter_rule

    try:
        sniff(**kwargs)
    except Exception as e:
        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'error',
            'detail': f'抓包错误: {e}'
        })

    elapsed = round(time.time() - start_time, 2)

    capture_log.append({
        'time': time.strftime("%H:%M:%S"),
        'event': 'done',
        'detail': f'抓包完成: 共 {len(packets_info)} 个包, 耗时 {elapsed}s'
    })

    return packets_info, capture_log


def capture_packets_socket(count=5, timeout=10):
    """使用原始套接字抓包（备选方案）"""
    packets_info = []
    capture_log = []

    capture_log.append({
        'time': time.strftime("%H:%M:%S"),
        'event': 'init',
        'detail': f'使用原始套接字模式, 目标 {count} 个包'
    })

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)

        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'start',
            'detail': '开始抓包 (原始套接字模式)...'
        })

        start_time = time.time()

        while len(packets_info) < count:
            try:
                raw_packet, addr = s.recvfrom(65535)
                pkt_time = time.strftime("%H:%M:%S.%f")[:-3]

                info = {
                    "id": len(packets_info) + 1,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_precise": pkt_time,
                    "src_ip": addr[0],
                    "dst_ip": "",
                    "protocol": "TCP",
                    "src_port": "",
                    "dst_port": "",
                    "tcp_flags": "",
                    "payload": "",
                    "payload_hex": raw_packet.hex()[:200],
                    "payload_length": 0,
                    "length": len(raw_packet),
                    "summary": f"TCP {addr[0]} → local"
                }

                # 解析 IP+TCP 头部
                if len(raw_packet) > 40:
                    ip_header = raw_packet[:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    info["src_ip"] = socket.inet_ntoa(iph[8])
                    info["dst_ip"] = socket.inet_ntoa(iph[9])
                    info["ttl"] = iph[5]

                    tcp_header = raw_packet[20:40]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    info["src_port"] = str(tcph[0])
                    info["dst_port"] = str(tcph[1])
                    info["seq_num"] = tcph[2]
                    info["ack_num"] = tcph[3]
                    info["tcp_flags"] = _parse_tcp_flags(tcph[5])
                    info["window_size"] = tcph[6]

                    payload = raw_packet[40:]
                    if payload:
                        info["payload_length"] = len(payload)
                        info["payload_hex"] = payload.hex()[:500]
                        try:
                            info["payload"] = payload.decode('utf-8', errors='replace')[:300]
                        except:
                            info["payload"] = ""

                    info["summary"] = f"TCP [{info['tcp_flags']}] {info['src_ip']}:{info['src_port']} → {info['dst_ip']}:{info['dst_port']}"

                packets_info.append(info)
                capture_log.append({
                    'time': pkt_time,
                    'event': 'packet',
                    'detail': info["summary"]
                })

            except socket.timeout:
                break

        s.close()
        elapsed = round(time.time() - start_time, 2)
        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'done',
            'detail': f'抓包完成: 共 {len(packets_info)} 个包, 耗时 {elapsed}s'
        })

    except PermissionError:
        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'error',
            'detail': '权限不足，需要 root/Administrator 权限'
        })
    except Exception as e:
        capture_log.append({
            'time': time.strftime("%H:%M:%S"),
            'event': 'error',
            'detail': f'错误: {e}'
        })

    return packets_info, capture_log


def capture_packets(count=10, timeout=15, interface=None):
    """抓取网络数据包，返回 (packets, capture_log)"""
    if HAS_SCAPY:
        return capture_packets_scapy(count=count, timeout=timeout, interface=interface)
    else:
        return capture_packets_socket(count=count, timeout=timeout)


def packets_to_json(packets_info):
    """将抓取的数据包列表转为 JSON 字符串"""
    return json.dumps(packets_info, ensure_ascii=False, indent=2)


def get_network_info():
    """获取本机网络信息"""
    info = {
        "hostname": socket.gethostname(),
        "interfaces": []
    }
    try:
        info["ip_address"] = socket.gethostbyname(info["hostname"])
    except:
        info["ip_address"] = "127.0.0.1"

    try:
        addrs = socket.getaddrinfo(info["hostname"], None)
        seen = set()
        for addr in addrs:
            ip = addr[4][0]
            if ip not in seen:
                seen.add(ip)
                info["interfaces"].append(ip)
    except:
        pass

    # scapy 接口信息
    if HAS_SCAPY:
        info["scapy_interfaces"] = _get_interfaces()

    return info


if __name__ == '__main__':
    print("网络数据采集模块测试")
    print("=" * 60)
    net_info = get_network_info()
    print(f"本机信息: {json.dumps(net_info, indent=2, default=str)}")
    print(f"scapy 可用: {HAS_SCAPY}")

    if HAS_SCAPY:
        print("\n抓取5个数据包...")
        packets, logs = capture_packets(count=5, timeout=10)
        print("\n抓包过程:")
        for log_entry in logs:
            print(f"  [{log_entry['time']}] {log_entry['detail']}")
        print(f"\n数据包详情:")
        for pkt in packets:
            print(f"  包{pkt['id']}: {pkt['summary']}")
