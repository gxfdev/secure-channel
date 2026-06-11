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

### 方式一：Docker 部署（推荐）

> **重要**: 必须使用 `--network host` 模式运行容器，否则跨主机通信和抓包功能不可用。
> Flask 默认监听 `0.0.0.0:5000`，确保外部主机可访问。

```bash
# 拉取镜像
docker pull ghcr.io/gxfdev/secure-channel:main

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

### 方式二：Docker Compose

```bash
# 创建 .env 文件设置接收端 IP
echo "RECEIVER_HOST=<接收端IP>" > .env

# 或通过命令行指定
RECEIVER_HOST=<接收端IP> docker compose up -d
```

### 方式三：直接运行

```bash
# 安装依赖
pip install -r requirements.txt

# 接收端
MODE=receiver FLASK_HOST=0.0.0.0 python app.py

# 发送端（将 <接收端IP> 替换为接收端的实际 IP）
MODE=sender RECEIVER_HOST=<接收端IP> FLASK_HOST=0.0.0.0 python app.py
```

### 跨主机通信排查

如果发送端无法访问接收端 Web 界面，按以下步骤排查：

1. **确认 Flask 监听地址**: `docker logs <容器名> | grep "Running on"`，必须显示 `0.0.0.0:5000`
2. **确认防火墙**: `firewall-cmd --list-ports` 或 `iptables -L -n`，确保 5000/tcp 和 9999/tcp 开放
3. **确认网络互通**: `ping <对方IP>` 测试基础连通性
4. **确认 SELinux**: 临时关闭 `setenforce 0`，或永久配置
5. **确认 Docker 网络模式**: 必须使用 `--network host`

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
