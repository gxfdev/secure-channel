#!/bin/bash
# 接收端一键部署脚本 (node7: 192.168.157.207)
# 自动拉取最新镜像 + 停止旧容器 + 启动新容器

IMAGE="crpi-4ppbczhsmgz5b9tt.cn-heyuan.personal.cr.aliyuncs.com/grcs/grcs:latest"
CONTAINER="netsec-receiver"

echo "===== 接收端一键部署 ====="

# 1. 停止并删除旧容器
echo "[1] 停止旧容器..."
docker rm -f $CONTAINER 2>/dev/null

# 2. 拉取最新镜像
echo "[2] 拉取最新镜像..."
docker pull $IMAGE

# 3. 启动新容器
echo "[3] 启动接收端容器..."
docker run -d --name $CONTAINER \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e MODE=receiver \
  -e FLASK_HOST=0.0.0.0 \
  -e FLASK_PORT=5001 \
  -e LISTEN_PORT=9999 \
  $IMAGE

# 4. 等待启动
sleep 2

# 5. 检查状态
echo "[4] 检查容器状态..."
docker ps | grep $CONTAINER
echo ""
docker logs $CONTAINER 2>&1 | tail -8

# 6. 开放防火墙
echo "[5] 开放防火墙端口..."
sudo firewall-cmd --add-port=9999/tcp --permanent 2>/dev/null
sudo firewall-cmd --add-port=5001/tcp --permanent 2>/dev/null
sudo firewall-cmd --reload 2>/dev/null

echo ""
echo "===== 接收端部署完成 ====="
echo "Web界面: http://192.168.157.207:5001"
echo "协商端口: 9999"
