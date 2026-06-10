"""
网络数据采集模块
使用 scapy 抓取真实网络数据包，提取有效载荷
如果 scapy 不可用，则使用 socket 原始套接字作为备选方案
"""
import socket
import struct
import time
import json
import threading

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def capture_packets_scapy(count=10, timeout=15, interface=None, filter_rule="ip"):
    """
    使用 scapy 抓取网络数据包
    参数:
        count: 抓取数据包数量
        timeout: 超时时间（秒）
        interface: 网卡接口（None=自动选择）
        filter_rule: BPF 过滤规则
    返回:
        list[dict], 抓取到的数据包信息列表
    """
    if not HAS_SCAPY:
        raise RuntimeError("scapy 未安装，请运行: pip install scapy")

    packets_info = []

    def process_packet(pkt):
        info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "",
            "dst_ip": "",
            "protocol": "",
            "src_port": "",
            "dst_port": "",
            "payload": "",
            "payload_hex": "",
            "length": 0
        }

        if IP in pkt:
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
            info["length"] = len(pkt)

            if TCP in pkt:
                info["protocol"] = "TCP"
                info["src_port"] = str(pkt[TCP].sport)
                info["dst_port"] = str(pkt[TCP].dport)
            elif UDP in pkt:
                info["protocol"] = "UDP"
                info["src_port"] = str(pkt[UDP].sport)
                info["dst_port"] = str(pkt[UDP].dport)
            elif ICMP in pkt:
                info["protocol"] = "ICMP"
            else:
                info["protocol"] = str(pkt[IP].proto)

            if Raw in pkt:
                raw_data = bytes(pkt[Raw])
                info["payload_hex"] = raw_data.hex()
                try:
                    info["payload"] = raw_data.decode('utf-8', errors='replace')[:200]
                except:
                    info["payload"] = ""
            else:
                info["payload_hex"] = ""
                info["payload"] = ""

        packets_info.append(info)

    print(f"  [抓包] 开始抓取 {count} 个数据包（超时{timeout}秒）...")

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

    sniff(**kwargs)

    print(f"  [抓包] 抓取完成，共 {len(packets_info)} 个数据包")
    return packets_info


def capture_packets_socket(count=5, timeout=10):
    """
    使用原始套接字抓取网络数据包（备选方案，无需 scapy）
    仅适用于 Linux/Mac，需要 root 权限
    """
    packets_info = []

    try:
        # 创建原始套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)

        print(f"  [抓包-Socket] 开始抓取（超时{timeout}秒）...")

        while len(packets_info) < count:
            try:
                raw_packet, addr = s.recvfrom(65535)
                info = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": addr[0],
                    "dst_ip": socket.gethostbyname(socket.gethostname()),
                    "protocol": "TCP",
                    "src_port": "",
                    "dst_port": "",
                    "payload": "",
                    "payload_hex": raw_packet.hex()[:200],
                    "length": len(raw_packet)
                }

                # 解析 TCP 头部（IP头20字节后）
                if len(raw_packet) > 40:
                    ip_header = raw_packet[:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    info["src_ip"] = socket.inet_ntoa(iph[8])
                    info["dst_ip"] = socket.inet_ntoa(iph[9])

                    tcp_header = raw_packet[20:40]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    info["src_port"] = str(tcph[0])
                    info["dst_port"] = str(tcph[1])

                    payload = raw_packet[40:]
                    if payload:
                        info["payload_hex"] = payload.hex()[:200]
                        try:
                            info["payload"] = payload.decode('utf-8', errors='replace')[:200]
                        except:
                            info["payload"] = ""

                packets_info.append(info)

            except socket.timeout:
                break

        s.close()

    except PermissionError:
        print("  [抓包-Socket] 权限不足，需要 root 权限")
    except Exception as e:
        print(f"  [抓包-Socket] 错误: {e}")

    print(f"  [抓包-Socket] 抓取完成，共 {len(packets_info)} 个数据包")
    return packets_info


def capture_packets(count=10, timeout=15, interface=None):
    """
    抓取网络数据包（自动选择可用方法）
    优先使用 scapy，不可用时回退到 socket
    """
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

    # 获取所有网络接口地址
    try:
        addrs = socket.getaddrinfo(info["hostname"], None)
        seen = set()
        for addr in addrs:
            ip = addr[4][0]
            if ip not in seen and not ip.startswith('127.'):
                seen.add(ip)
                info["interfaces"].append(ip)
    except:
        pass

    return info


if __name__ == '__main__':
    print("网络数据采集模块测试")
    print("=" * 60)

    net_info = get_network_info()
    print(f"本机信息: {json.dumps(net_info, indent=2)}")
    print(f"scapy 可用: {HAS_SCAPY}")

    if HAS_SCAPY:
        print("\n尝试抓取5个数据包（10秒超时）...")
        packets = capture_packets(count=5, timeout=10)
        for i, pkt in enumerate(packets):
            print(f"\n包{i+1}: {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']} [{pkt['protocol']}]")
            if pkt['payload']:
                print(f"  载荷: {pkt['payload'][:80]}")
    else:
        print("\nscapy 未安装，请运行: pip install scapy")
