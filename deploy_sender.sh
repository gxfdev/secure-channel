#!/bin/bash
# 发送端一键部署脚本 (node8: 192.168.157.208)
# 自动拉取最新镜像 + 停止旧容器 + 启动新容器

VERSION="${1:-latest}"
REGISTRY="crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcsd/grcs"
IMAGE="$REGISTRY:$VERSION"
CONTAINER="netsec-sender"

echo "===== 发送端一键部署 (版本: $VERSION) ====="

# 1. 停止并删除旧容器
echo "[1] 停止旧容器..."
docker rm -f $CONTAINER 2>/dev/null

# 2. 拉取镜像
echo "[2] 拉取镜像 $IMAGE ..."
docker pull $IMAGE

# 3. 启动新容器
echo "[3] 启动发送端容器..."
docker run -d --name $CONTAINER \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=sender \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5000 \
  -e LISTEN_PORT=9999 \
  $IMAGE

# 4. 等待启动
sleep 2

# 5. 检查状态
echo "[4] 检查容器状态..."
docker ps | grep $CONTAINER
echo ""
docker logs $CONTAINER 2>&1 | tail -8

echo ""
echo "===== 发送端部署完成 ====="
echo "镜像版本: $VERSION"
echo "Web界面: http://192.168.157.208:5000"
echo "连接目标: 192.168.157.207:9999"
echo ""
echo "用法: bash deploy_sender.sh [版本号]"
echo "示例: bash deploy_sender.sh 1.5.0"
echo "      bash deploy_sender.sh latest"
