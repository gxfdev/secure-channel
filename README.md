# Secure Channel - 网络安全传输演示系统

基于自实现加密算法的网络安全传输演示系统，实现两台主机之间的安全加密通信，包含完整的密钥协商、数据加密、消息认证和数字签名流程。

## 安全特性

| 特性 | 实现方式 | 算法 |
|------|----------|------|
| 机密性 | 对称加密 | AES-128-CBC (PKCS7填充) |
| 完整性 | 消息认证码 | HMAC-SHA256 (RFC 2104) |
| 真实性 | 数字签名 | RSA-SHA256 签名验证 |
| 不可否认性 | 私钥签名 | RSA 私钥签名 + 公钥验证 |
| 密钥安全 | 密钥协商 | Diffie-Hellman (RFC 3526 2048-bit) |

## 通信流程

```
发送端                                    接收端
  |                                         |
  |------- TCP 三次握手 -------------------->|
  |                                         |
  |------- 协商请求 ----------------------->|
  |<------ RSA公钥 + DH公钥 + 签名 ---------|
  |------- RSA公钥 + DH公钥 + 签名 -------->|
  |       (双方验证对方签名)                  |
  |       (计算共享会话密钥)                  |
  |                                         |
  |------- AES加密数据 + HMAC + 签名 ------->|
  |       (接收端验证签名 → 验证HMAC → 解密)  |
  |                                         |
  |<------ AES加密数据 + HMAC + 签名 --------|
  |       (发送端验证签名 → 验证HMAC → 解密)  |
```

## 自实现算法

所有加密算法均为自实现，未使用任何第三方加密库：

- **SHA-256** (`sha256.py`) - 遵循 FIPS 180-4 标准
- **AES-128** (`aes.py`) - CBC 模式，PKCS7 填充
- **RSA** (`rsa.py`) - 密钥生成、加解密、数字签名与验证
- **HMAC-SHA256** (`hmac_sha256.py`) - 遵循 RFC 2104 标准
- **DH** (`dh.py`) - Diffie-Hellman 密钥协商，RFC 3526 2048-bit MODP 素数群

## 快速开始

### 前提条件

- 两台互通的主机（虚拟机或物理机）
- 防火墙开放 5000/tcp（Web界面）和 9999/tcp（数据传输）
- Docker 已安装

### 镜像拉取

#### 直接拉取

```bash
docker pull ghcr.io/gxfdev/secure-channel:main
```

#### 通过代理拉取（国内加速）

如果直接拉取 GHCR 镜像速度过慢，可通过以下方式配置代理：

**方式一：配置 Docker Daemon 代理**

```bash
# 创建 Docker 代理配置目录
sudo mkdir -p /etc/systemd/system/docker.service.d

# 创建代理配置文件（将代理地址替换为你自己的）
sudo cat > /etc/systemd/system/docker.service.d/proxy.conf << 'EOF'
[Service]
Environment="HTTP_PROXY=http://你的代理地址:端口"
Environment="HTTPS_PROXY=http://你的代理地址:端口"
Environment="NO_PROXY=localhost,127.0.0.1,192.168.*"
EOF

# 重载配置并重启 Docker
sudo systemctl daemon-reload
sudo systemctl restart docker

# 验证代理配置
docker info | grep -i proxy
```

**方式二：临时使用代理拉取**

```bash
# 在拉取命令前设置环境变量
HTTP_PROXY=http://你的代理地址:端口 HTTPS_PROXY=http://你的代理地址:端口 \
  docker pull ghcr.io/gxfdev/secure-channel:main
```

**方式三：使用国内镜像加速**

```bash
# 配置 Docker 镜像加速器
sudo cat > /etc/docker/daemon.json << 'EOF'
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com",
    "https://docker.mirrors.ustc.edu.cn"
  ]
}
EOF

sudo systemctl restart docker
```

**方式四：本地构建镜像（无需拉取）**

```bash
# 克隆仓库后本地构建
git clone https://github.com/gxfdev/secure-channel.git
cd secure-channel
docker build -t secure-channel:local .
```

### 部署运行

> **重要**: 必须使用 `--network host` 模式运行容器，否则跨主机通信和抓包功能不可用。
> Flask 默认监听 `0.0.0.0:5000`，确保外部主机可访问。

```bash
# ========== 接收端 VM ==========
docker run -d --name netsec-receiver \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /home/user/captured_data:/app/captured_data \
  -e MODE=receiver \
  -e FLASK_HOST=0.0.0.0 \
  ghcr.io/gxfdev/secure-channel:main

# ========== 发送端 VM ==========
# 将 <接收端IP> 替换为接收端 VM 的实际 IP 地址
docker run -d --name netsec-sender \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /home/user/captured_data:/app/captured_data \
  -e MODE=sender \
  -e RECEIVER_HOST=<接收端IP> \
  -e FLASK_HOST=0.0.0.0 \
  ghcr.io/gxfdev/secure-channel:main
```

**验证部署**:
```bash
# 在接收端 VM 上检查 Flask 是否监听 0.0.0.0
docker logs netsec-receiver 2>&1 | grep "Running on"
# 应看到: Running on http://0.0.0.0:5000

# 在发送端 VM 上测试访问接收端
curl http://<接收端IP>:5000/
# 应返回 HTML 内容
```

### Docker Compose 部署

```bash
# 创建 .env 文件设置接收端 IP
echo "RECEIVER_HOST=<接收端IP>" > .env

# 或通过命令行指定
RECEIVER_HOST=<接收端IP> docker compose up -d
```

### 直接运行（无 Docker）

```bash
# 安装依赖
pip install -r requirements.txt

# 接收端
MODE=receiver FLASK_HOST=0.0.0.0 python app.py

# 发送端（将 <接收端IP> 替换为接收端的实际 IP）
MODE=sender RECEIVER_HOST=<接收端IP> FLASK_HOST=0.0.0.0 python app.py
```

## 数据存储说明

### 存储路径

| 数据类型 | 容器内路径 | 宿主机挂载路径 | 文件命名规则 |
|----------|-----------|---------------|-------------|
| 抓包数据 | `/app/captured_data/capture_*.json` | 通过 `-v` 参数指定 | `capture_{毫秒时间戳}.json` |
| 接收数据 | `/app/captured_data/received_*.json` | 通过 `-v` 参数指定 | `received_{毫秒时间戳}.json` |
| RSA 密钥 | `/app/captured_data/rsa_key_*.pem` | 通过 `-v` 参数指定 | `rsa_key_pub.pem` / `rsa_key_priv.pem` |

### 查看数据文件

**方式一：通过 Web 界面**

访问 `http://主机IP:5000/api/data_files` 可查看所有数据文件列表，访问 `http://主机IP:5000/api/data_files/{文件名}` 可查看具体文件内容。

**方式二：通过命令行**

```bash
# 查看容器内的数据文件
docker exec netsec-receiver ls -la /app/captured_data/

# 查看具体文件内容
docker exec netsec-receiver cat /app/captured_data/capture_xxx.json

# 如果挂载了卷，直接在宿主机查看
ls -la /home/user/captured_data/
cat /home/user/captured_data/capture_xxx.json

# 用 jq 格式化查看（如果安装了 jq）
cat /home/user/captured_data/capture_xxx.json | python -m json.tool
```

**方式三：复制到宿主机**

```bash
# 从容器复制数据文件到宿主机
docker cp netsec-receiver:/app/captured_data/ ./local_data/
```

### 数据文件格式

每个抓包文件为 JSON 格式，包含数据包数组：

```json
[
  {
    "id": 1,
    "timestamp": "2024-01-01 12:00:00",
    "protocol": "TCP",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "src_port": "5000",
    "dst_port": "9999",
    "tcp_flags": "SYN",
    "length": 64,
    "payload": "...",
    "summary": "TCP [SYN] 192.168.1.10:5000 → 192.168.1.20:9999"
  }
]
```

## 跨主机通信排查

如果发送端无法访问接收端，按以下步骤逐一排查：

### 1. 确认 Flask 监听地址

```bash
docker logs netsec-receiver 2>&1 | grep "Running on"
# 必须显示: Running on http://0.0.0.0:5000
# 如果显示 127.0.0.1:5000，说明 FLASK_HOST 未正确设置
```

### 2. 确认防火墙规则

```bash
# CentOS 7 / firewalld
sudo firewall-cmd --list-ports
sudo firewall-cmd --add-port=5000/tcp --permanent
sudo firewall-cmd --add-port=9999/tcp --permanent
sudo firewall-cmd --reload

# 或使用 iptables
sudo iptables -L -n | grep -E "5000|9999"

# 临时关闭防火墙（仅测试用）
sudo systemctl stop firewalld
```

### 3. 确认网络互通

```bash
# 测试基础连通性
ping <对方IP>

# 测试端口连通性
curl -v http://<对方IP>:5000/
# 或
telnet <对方IP> 5000
```

### 4. 确认 SELinux

```bash
# 查看状态
getenforce

# 临时关闭（需 root）
sudo setenforce 0

# 永久关闭
sudo sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
```

### 5. 确认 Docker 网络模式

```bash
# 必须使用 --network host 模式
docker inspect netsec-receiver | grep NetworkMode
# 应显示: "host"
```

### 6. 确认端口占用

```bash
# 检查 5000 和 9999 端口是否被占用
ss -tlnp | grep -E "5000|9999"
netstat -tlnp | grep -E "5000|9999"
```

## 使用说明

1. 打开发送端 Web 界面 `http://发送端IP:5000`
2. 在「建立连接」处输入接收端 IP 和端口，点击「连接」
3. 观察 TCP 三次握手和 DH 密钥协商过程
4. 点击「抓取数据包」采集真实网络流量
5. 点击「加密并发送」将数据加密传输
6. 在接收端 Web 界面查看解密后的原始数据

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MODE` | `sender` | 运行模式：`sender` 或 `receiver` |
| `RECEIVER_HOST` | `127.0.0.1` | 接收端 IP 地址 |
| `RECEIVER_PORT` | `9999` | 接收端监听端口 |
| `LISTEN_PORT` | `9999` | 本端监听端口 |
| `RSA_BITS` | `512` | RSA 密钥位数 |
| `DATA_DIR` | `./captured_data` | 数据存储目录 |
| `FLASK_HOST` | `0.0.0.0` | Flask 监听地址，跨主机必须设为 `0.0.0.0` |
| `FLASK_PORT` | `5000` | Flask 监听端口 |

## 项目结构

```
├── sha256.py          # SHA-256 哈希算法
├── aes.py             # AES-128-CBC 对称加密
├── rsa.py             # RSA 公钥加密 + 数字签名
├── hmac_sha256.py     # HMAC-SHA256 消息认证码
├── dh.py              # Diffie-Hellman 密钥协商
├── capture.py         # 网络数据包采集（scapy）
├── network.py         # Socket 网络传输
├── app.py             # Flask Web 应用
├── sender.py          # CLI 发送端
├── receiver.py        # CLI 接收端
├── templates/
│   └── index.html     # Web 前端界面
├── Dockerfile         # Docker 镜像构建
├── docker-compose.yml # Docker Compose 编排
├── requirements.txt   # Python 依赖
└── .github/workflows/
    ├── ci.yml         # CI 测试工作流
    └── docker.yml     # Docker 镜像构建推送
```

## CI/CD

- **CI 测试**: 每次 push/PR 自动运行所有算法单元测试 + 完整流程集成测试
- **Docker 构建**: push 到 main 分支自动构建镜像并推送到 GHCR

## License

MIT
