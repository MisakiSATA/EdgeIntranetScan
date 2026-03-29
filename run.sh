#!/bin/bash
# 边缘安全审计工具启动脚本

cd "$(dirname "$0")"

echo "边缘安全审计工具 v2.0"
echo "======================"

# 找到python3路径
PYTHON=$(which python3 2>/dev/null || echo "/usr/bin/python3")

# 检查Python
if [ ! -f "$PYTHON" ]; then
    echo "错误: 未找到 python3"
    exit 1
fi

echo "Python: $PYTHON"

# 检查nmap
if ! command -v nmap &> /dev/null; then
    echo "警告: nmap未安装，请运行: sudo apt install nmap"
fi

# 检查tcpdump
if ! command -v tcpdump &> /dev/null; then
    echo "警告: tcpdump未安装，流量分析功能需要: sudo apt install tcpdump"
fi

# 创建目录
mkdir -p data logs

# 获取IP
IP=$(hostname -I | awk '{print $1}')
if [ -z "$IP" ]; then
    IP="localhost"
fi

echo ""
echo "启动服务..."
echo "访问地址: http://$IP:8080"
echo ""

# 启动（让Python自己处理模块缺失的情况）
exec "$PYTHON" app.py
