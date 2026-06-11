FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖（scapy 需要）
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制所有源代码
COPY . .

# Web 端口
EXPOSE 5000
# 数据传输端口
EXPOSE 9999

# 默认发送端模式，可通过环境变量 MODE=receiver 切换
ENV MODE=sender
ENV RECEIVER_HOST=127.0.0.1
ENV RECEIVER_PORT=9999
ENV LISTEN_PORT=9999
ENV RSA_BITS=512
ENV DATA_DIR=/app/captured_data
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000

# 创建数据存储目录
RUN mkdir -p /app/captured_data

# 数据目录可作为卷挂载
VOLUME /app/captured_data

CMD ["python", "app.py"]
