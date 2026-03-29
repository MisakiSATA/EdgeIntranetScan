# 边缘安全审计工具 v2.0

基于 Orange Pi Zero 2W 的轻量级网络安全审计系统

## 功能特性

- **网络发现** - 自动扫描局域网内的活跃主机
- **端口扫描** - 检测开放端口和服务版本
- **漏洞扫描** - HTTP安全头检查、敏感路径检测、注入检测
- **流量分析** - 网络流量捕获与分析（需要tcpdump）
- **审计报告** - 生成安全审计报告

## 系统要求

- ARM Linux (Armbian/Ubuntu)
- 512MB+ RAM
- Python 3.8+

## 安装依赖

```bash
# 更新系统
sudo apt update

# 安装Python依赖
pip3 install -r requirements.txt

# 安装nmap（必需）
sudo apt install nmap

# 安装tcpdump（可选，用于流量分析）
sudo apt install tcpdump
```

## 使用方法

### 启动服务

```bash
bash run.sh
```

### 访问界面

```
http://<IP>:8080
```

## 目录结构

```
project2/
├── app.py              # 主程序
├── run.sh              # 启动脚本
├── requirements.txt     # Python依赖
├── modules/            # 功能模块
│   ├── network_discovery.py
│   ├── port_scanner.py
│   └── vuln_scanner.py
├── templates/          # HTML模板
├── static/             # 静态资源
│   └── vendor/         # Bootstrap CSS/JS
├── data/               # 数据库和扫描结果
└── logs/               # 日志文件
```

## 测试目标

### 本地网络
- `192.168.x.0/24` - 您的局域网
- `127.0.0.1:8080` - 本机Flask服务

### 公共测试站点
- `http://testphp.vulnweb.com`
- `http://httpforever.com`
- `http://www.baidu.com`

## 注意事项

1. 端口扫描和漏洞扫描可能需要较长时间
2. 扫描外部目标前请确保有合法授权
3. tcpdump需要root权限才能运行
4. 建议在测试环境中使用

## 版本信息

- 版本: v2.0.0
- 更新日期: 2026-03-29
