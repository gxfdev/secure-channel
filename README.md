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
  |------- TCP 三次握手 -------------------->|   ① SYN
  |<------ SYN+ACK -------------------------|   ② SYN+ACK
  |------- ACK ---------------------------->|   ③ ACK
  |                                         |
  |------- 我的RSA公钥 --------------------->|   ④ 交换RSA公钥
  |<------ 你的RSA公钥 ---------------------|
  |                                         |
  |------- 我的DH公钥+RSA签名 ------------->|   ⑤ 交换DH公钥(带签名)
  |<------ 你的DH公钥+RSA签名 --------------|
  |       (双方用对方RSA公钥验证签名)         |
  |       (双方独立计算相同的会话密钥)         |
  |                                         |
  |------- AES加密数据+HMAC+RSA签名 ------->|   ⑥ 加密传输
  |       (验证签名→验证HMAC→AES解密)        |
```

## 自实现算法

所有加密算法均为自实现，未使用任何第三方加密库：

- **SHA-256** (`sha256.py`) - 遵循 FIPS 180-4 标准
- **AES-128** (`aes.py`) - CBC 模式，PKCS7 填充
- **RSA** (`rsa.py`) - 密钥生成、加解密、数字签名与验证
- **HMAC-SHA256** (`hmac_sha256.py`) - 遵循 RFC 2104 标准
- **DH** (`dh.py`) - Diffie-Hellman 密钥协商，RFC 3526 2048-bit MODP 素数群

---

## 两台局域网虚拟机部署（完整指南）

### 网络拓扑

```
┌─────────────────────┐       局域网        ┌─────────────────────┐
│    发送端 VM         │                     │    接收端 VM         │
│  IP: 192.168.x.10   │◄──────────────────►│  IP: 192.168.x.20   │
│                     │                     │                     │
│  Web: :5000         │    TCP :9999        │  Web: :5001         │
│  协商: :9999        │◄──────────────────►│  协商: :9999        │
└─────────────────────┘                     └─────────────────────┘

端口说明:
  - 5000/5001 : Web 管理界面（浏览器访问）
  - 9999      : 密钥协商 + 数据传输端口
```

### 端口与角色说明

| 角色 | Web 端口 | 协商端口 | 行为 |
|------|---------|---------|------|
| **发送端** | 5000 | 9999 | **主动**连接接收端的9999端口 |
| **接收端** | 5001 | 9999 | **被动**监听9999端口，等待发送端连接 |

> 发送端连接的是**接收端的9999端口**，不是5001端口。5001只是接收端的Web界面。

### 第一步：两台 VM 都安装 Docker

```bash
# CentOS / RHEL
sudo yum install -y docker
sudo systemctl enable --now docker

# Ubuntu / Debian
sudo apt install -y docker.io
sudo systemctl enable --now docker

# 验证
docker --version
```

### 第二步：开放防火墙端口

**两台 VM 都要执行：**

```bash
# CentOS 7 (firewalld)
sudo firewall-cmd --add-port=5000/tcp --permanent
sudo firewall-cmd --add-port=5001/tcp --permanent
sudo firewall-cmd --add-port=9999/tcp --permanent
sudo firewall-cmd --reload

# 或临时关闭防火墙（仅测试用）
sudo systemctl stop firewalld
```

### 第三步：拉取镜像

**两台 VM 都要执行：**

```bash
# 登录阿里云 ACR
docker login --username=Agr123 crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com

# 拉取镜像
docker pull crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcs/grcs:latest
```

### 第四步：启动接收端容器

**在接收端 VM 上执行：**

```bash
docker run -d --name netsec-receiver \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=receiver \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5001 \
  -e LISTEN_PORT=9999 \
  crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcs/grcs:latest
```

验证接收端启动成功：
```bash
docker logs netsec-receiver 2>&1 | tail -10
# 应看到:
#   协商服务器 监听 0.0.0.0:9999
#   Web 界面: http://0.0.0.0:5001
```

浏览器打开 `http://<接收端IP>:5001`，点击 **「我是接收端」**。

### 第五步：启动发送端容器

**在发送端 VM 上执行：**

```bash
docker run -d --name netsec-sender \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=sender \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5000 \
  -e LISTEN_PORT=9999 \
  crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcs/grcs:latest
```

验证发送端启动成功：
```bash
docker logs netsec-sender 2>&1 | tail -10
# 应看到:
#   协商服务器 监听 0.0.0.0:9999
#   Web 界面: http://0.0.0.0:5000
```

浏览器打开 `http://<发送端IP>:5000`，点击 **「我是发送端」**。

### 第六步：建立连接

1. 在发送端 Web 界面，输入接收端的 IP 和协商端口：
   - **目标 IP**: 接收端 VM 的 IP（如 `192.168.157.207`）
   - **目标端口**: `9999`（接收端的协商端口，不是5001）

2. 点击 **「连接」**，观察 5 步密钥交换过程：
   - 步骤1: TCP 三次握手（显示真实的 seq/ack 序列号、标志位）
   - 步骤2: 交换 RSA 公钥
   - 步骤3: 交换 DH 公钥（带 RSA 数字签名）
   - 步骤4: 验证对方签名
   - 步骤5: 计算共享会话密钥

3. 全部显示 ✓ 表示连接成功

### 第七步：抓包 → 加密 → 发送 → 接收 → 解密

**发送端操作：**
1. 输入抓包数量，点击 **「抓取数据包」**
2. 选择一条抓到的数据包
3. 点击 **「加密并发送」**（数据经过 AES加密 + HMAC认证 + RSA签名后发出）

**接收端查看：**
1. 打开接收端 Web 界面 `http://<接收端IP>:5001`
2. 点击 **「刷新」**，查看接收到的数据
3. 确认 HMAC 验证 ✓、签名验证 ✓、解密数据与原文一致

### 连接失败排查

> **核心原理**：发送端通过 TCP 连接到接收端的 9999 端口，接收端的协商服务器必须在该端口上监听才能接受连接。

**排查步骤（按顺序执行）：**

```bash
# ====== 第1步：确认两台 VM 网络互通 ======
# 在发送端 VM 上执行：
ping <接收端IP>
# 如果 ping 不通，说明网络层不通，检查 VM 网络配置和虚拟交换机设置

# ====== 第2步：确认接收端容器正常运行 ======
# 在接收端 VM 上执行：
docker ps | grep netsec-receiver
# 如果没有输出，说明容器没启动，重新启动容器

# ====== 第3步：确认接收端协商服务器已启动 ======
# 在接收端 VM 上执行：
docker logs netsec-receiver 2>&1 | grep "监听"
# 应看到: [协商服务器] 监听 0.0.0.0:9999
# 如果没有，说明协商服务器启动失败，尝试重启：
docker restart netsec-receiver

# ====== 第4步：确认接收端 9999 端口可达 ======
# 在发送端 VM 上执行：
curl -v http://<接收端IP>:5001/     # 先测试 Web 端口
telnet <接收端IP> 9999              # 再测试协商端口
# 如果 Web 端口通但协商端口不通，说明防火墙只开了 5001

# ====== 第5步：确认防火墙已开放 9999 端口 ======
# 在接收端 VM 上执行：
sudo firewall-cmd --list-ports
# 如果没有 9999/tcp，添加：
sudo firewall-cmd --add-port=9999/tcp --permanent
sudo firewall-cmd --add-port=5001/tcp --permanent
sudo firewall-cmd --reload

# 或临时关闭防火墙（仅测试用）：
sudo systemctl stop firewalld

# ====== 第6步：确认 SELinux 未阻止 ======
getenforce
sudo setenforce 0  # 临时关闭

# ====== 第7步：使用 Web 界面的诊断工具 ======
# 在发送端 Web 界面点击「测试连通性」按钮
# 该工具会自动检测：DNS解析 → TCP连接 → 协议通信
# 根据提示信息定位问题
```

**常见问题及解决方案：**

| 现象 | 原因 | 解决方案 |
|------|------|---------|
| TCP连接超时 | 防火墙阻止或端口未监听 | 开放9999端口，确认容器运行 |
| 连接被拒绝 | 协商服务器未启动 | 重启容器或点「重启协商服务器」 |
| Web可访问但9999不通 | 只开了Web端口防火墙 | 同时开放9999端口 |
| 连接成功但发送失败 | 对方协商服务器已断开 | 接收端点「重启协商服务器」 |
| 抓包时间不对 | 容器时区默认UTC | 已修复：Dockerfile设置TZ=Asia/Shanghai |
| 抓不到9999端口流量 | 抓包时没有协商流量 | 先点连接再抓包，或选过滤器"仅协商端口" |

**正确的操作顺序：**

```
1. 接收端启动容器 → 打开Web界面 → 点「我是接收端」→ 确认状态显示"协商服务器运行中"
2. 发送端启动容器 → 打开Web界面 → 点「我是发送端」
3. 发送端点「测试连通性」→ 确认TCP连接成功
4. 发送端点「连接」→ 完成5步密钥协商
5. 发送端抓包 → 加密发送
6. 接收端点「刷新」→ 查看解密结果
```

---

## Docker Compose 部署

如果两台 VM 上都有项目源码，也可以用 docker compose：

```bash
# 接收端 VM
docker compose up -d receiver

# 发送端 VM（设置接收端 IP）
RECEIVER_HOST=192.168.157.207 docker compose up -d sender
```

## 单机测试

同一台机器上测试两个角色：

```bash
# 终端 1: 接收端
MODE=receiver FLASK_HOST=0.0.0.0 FLASK_PORT=5001 python app.py

# 终端 2: 发送端
MODE=sender FLASK_HOST=0.0.0.0 FLASK_PORT=5000 python app.py

# 浏览器打开 http://localhost:5000 → 选「我是发送端」→ 连接 127.0.0.1:9999
# 浏览器打开 http://localhost:5001 → 选「我是接收端」→ 等待
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MODE` | `sender` | 运行模式：`sender` 或 `receiver`（也可在 Web 界面切换） |
| `RECEIVER_HOST` | `127.0.0.1` | 接收端 IP 地址（发送端必须设为对方 VM 的 IP） |
| `RECEIVER_PORT` | `9999` | 接收端协商端口 |
| `LISTEN_PORT` | `9999` | 本端协商服务器监听端口 |
| `FLASK_HOST` | `0.0.0.0` | Flask 监听地址，跨主机必须设为 `0.0.0.0` |
| `FLASK_PORT` | `5000` | Flask Web 界面端口（接收端用 5001 避免冲突） |
| `RSA_BITS` | `512` | RSA 密钥位数 |
| `DATA_DIR` | `./captured_data` | 数据存储目录 |

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
├── templates/
│   └── index.html     # Web 前端界面
├── Dockerfile         # Docker 镜像构建
├── docker-compose.yml # Docker Compose 编排
├── requirements.txt   # Python 依赖
└── .github/workflows/
    ├── ci.yml         # CI 测试工作流
    └── docker.yml     # Docker 镜像构建推送（阿里云ACR）
```

## CI/CD

- **CI 测试**: 每次 push/PR 自动运行所有算法单元测试 + 完整流程集成测试
- **Docker 构建**: push 到 main 分支自动构建镜像并推送到阿里云 ACR

## License

MIT
