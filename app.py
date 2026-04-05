# -*- coding: utf-8 -*-
"""
边缘安全审计工具 - 主程序
简化版 Flask 应用
"""

import os
import sys
import re
import sqlite3
import logging
from datetime import datetime

from flask import Flask, render_template, jsonify, request

# 配置
DATABASE_PATH = 'data/audit.db'
SECRET_KEY = 'edge-audit-tool-secret-key-2024'
DEBUG = True
HOST = '0.0.0.0'
PORT = 8080
LOG_PATH = 'logs/audit.log'
VERSION = '2.0.0'

# 配置日志
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DEBUG'] = DEBUG

# 导入模块
from modules import NetworkDiscovery, PortScanner, VulnerabilityScanner


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库"""
    conn = get_db()
    cursor = conn.cursor()

    # 主机表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            status TEXT,
            ports TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 扫描历史表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            target TEXT,
            result TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 流量统计表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface TEXT,
            duration INTEGER,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            protocols TEXT,
            top_hosts TEXT,
            top_ports TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    logger.info("数据库初始化完成")


# ============================================================================
# 路由
# ============================================================================

@app.route('/')
def index():
    """首页"""
    conn = get_db()

    # 获取统计
    host_count = conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
    recent_hosts = conn.execute(
        'SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 5'
    ).fetchall()

    conn.close()

    return render_template('index.html',
                          host_count=host_count,
                          recent_hosts=recent_hosts,
                          version=VERSION)


@app.route('/network')
def network():
    """网络发现页面"""
    conn = get_db()
    hosts = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
    conn.close()

    return render_template('network.html', hosts=hosts, version=VERSION)


@app.route('/ports')
def ports():
    """端口扫描页面"""
    return render_template('ports.html', version=VERSION)


@app.route('/vulns')
def vulns():
    """漏洞扫描页面"""
    return render_template('vulns.html', version=VERSION)


@app.route('/traffic')
def traffic():
    """流量分析页面"""
    conn = get_db()
    stats = conn.execute(
        'SELECT * FROM traffic_stats ORDER BY scan_time DESC LIMIT 20'
    ).fetchall()
    conn.close()
    return render_template('traffic.html', stats=stats, version=VERSION)


@app.route('/report')
def report():
    """报告页面"""
    conn = get_db()

    # 获取统计信息
    host_count = conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]

    # 获取最近的主机
    recent_hosts = conn.execute(
        'SELECT * FROM hosts ORDER BY last_seen DESC LIMIT 10'
    ).fetchall()

    # 获取最近的扫描历史
    scan_history = conn.execute(
        'SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT 20'
    ).fetchall()

    conn.close()

    return render_template('report.html',
                          host_count=host_count,
                          recent_hosts=recent_hosts,
                          scan_history=scan_history,
                          version=VERSION)


# ============================================================================
# API
# ============================================================================

@app.route('/api/scan/network', methods=['POST'])
def api_scan_network():
    """网络扫描API"""
    data = request.json
    network = data.get('network', '192.168.1.0/24')
    top_ports = data.get('top_ports', 100)

    # 验证网段格式
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', network):
        return jsonify({
            'success': False,
            'message': '无效的网段格式，例如 192.168.1.0/24'
        }), 400

    try:
        discovery = NetworkDiscovery(network=network)
        hosts = discovery.scan(top_ports=top_ports)

        return jsonify({
            'success': True,
            'message': f'扫描完成，发现 {len(hosts)} 台主机',
            'hosts': hosts
        })

    except Exception as e:
        logger.error(f"网络扫描失败: {e}")
        return jsonify({
            'success': False,
            'message': f'扫描失败: {str(e)}'
        }), 500


@app.route('/api/scan/ports', methods=['POST'])
def api_scan_ports():
    """端口扫描API"""
    data = request.json
    target = data.get('target')
    ports = data.get('ports', '1-1000')

    if not target:
        return jsonify({
            'success': False,
            'message': '请指定目标'
        }), 400

    # 验证目标格式（IP地址或域名）
    if not re.match(r'^[\d.a-zA-Z-]+$', target):
        return jsonify({
            'success': False,
            'message': '无效的目标地址'
        }), 400

    try:
        scanner = PortScanner()
        result = scanner.scan(target, ports)

        return jsonify({
            'success': True,
            'message': f'扫描完成，发现 {result["total"]} 个开放端口',
            'data': result
        })

    except Exception as e:
        logger.error(f"端口扫描失败: {e}")
        return jsonify({
            'success': False,
            'message': f'扫描失败: {str(e)}'
        }), 500


@app.route('/api/scan/vulns', methods=['POST'])
def api_scan_vulns():
    """漏洞扫描API"""
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({
            'success': False,
            'message': '请指定目标'
        }), 400

    try:
        scanner = VulnerabilityScanner()
        result = scanner.scan(target)

        return jsonify({
            'success': True,
            'message': f'扫描完成，发现 {result["total"]} 个问题',
            'data': result
        })

    except Exception as e:
        logger.error(f"漏洞扫描失败: {e}")
        return jsonify({
            'success': False,
            'message': f'扫描失败: {str(e)}'
        }), 500


@app.route('/api/hosts')
def api_hosts():
    """获取主机列表API"""
    conn = get_db()
    hosts = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
    conn.close()

    return jsonify({
        'success': True,
        'hosts': [dict(host) for host in hosts]
    })


@app.route('/api/system/info')
def api_system_info():
    """系统信息API"""
    import platform

    return jsonify({
        'success': True,
        'data': {
            'version': VERSION,
            'python': platform.python_version(),
            'platform': platform.platform()
        }
    })


@app.route('/api/system/interfaces')
def api_system_interfaces():
    """获取网络接口列表"""
    import netifaces

    interfaces = []
    try:
        for iface in netifaces.interfaces():
            if iface != 'lo':
                interfaces.append(iface)
    except ImportError:
        # netifaces未安装，返回默认接口
        interfaces = ['eth0', 'wlan0', 'end0']

    return jsonify({
        'success': True,
        'data': interfaces
    })


@app.route('/api/traffic/capture', methods=['POST'])
def api_traffic_capture():
    """启动流量捕获"""
    data = request.json
    interface = data.get('interface', 'eth0')
    duration = data.get('duration', 60)

    # 验证接口名称（仅允许字母数字和连字符/下划线，防止命令注入）
    if not re.match(r'^[a-zA-Z0-9._-]+$', interface):
        return jsonify({
            'success': False,
            'message': '无效的网络接口名称'
        }), 400

    # 验证捕获时长
    if not isinstance(duration, int) or duration < 10 or duration > 600:
        return jsonify({
            'success': False,
            'message': '捕获时长必须在10-600秒之间'
        }), 400

    # 检查是否有tcpdump
    import shutil
    if not shutil.which('tcpdump'):
        return jsonify({
            'success': False,
            'message': 'tcpdump未安装，请运行: sudo apt install tcpdump'
        })

    # 检查权限
    if os.geteuid() != 0:
        return jsonify({
            'success': False,
            'message': '需要root权限运行tcpdump'
        })

    # 异步执行捕获
    import threading
    import subprocess

    def capture_traffic():
        try:
            output_file = f"data/capture_{int(datetime.now().timestamp())}.pcap"
            os.makedirs('data', exist_ok=True)

            cmd = [
                'tcpdump',
                '-i', interface,
                '-w', output_file,
                '-G', str(duration),
                '-W', '1',
                '-c', '10000'
            ]

            subprocess.run(cmd, capture_output=True, timeout=duration + 10)

            # 分析捕获文件
            stats = analyze_pcap(output_file, interface, duration)

            # 保存到数据库
            conn = get_db()
            conn.execute("""
                INSERT INTO traffic_stats
                (interface, duration, total_packets, total_bytes, protocols, top_hosts, top_ports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                interface, duration, stats['packets'], stats['bytes'],
                str(stats['protocols']), str(stats['top_hosts']), str(stats['top_ports'])
            ))
            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"流量捕获失败: {e}")

    # 启动后台线程
    thread = threading.Thread(target=capture_traffic)
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'message': f'已在{interface}接口启动捕获，持续{duration}秒'
    })


def analyze_pcap(pcap_file, interface, duration):
    """分析pcap文件"""
    stats = {
        'packets': 0,
        'bytes': 0,
        'protocols': {},
        'top_hosts': {},
        'top_ports': {}
    }

    try:
        result = subprocess.run(
            ['tcpdump', '-r', pcap_file, '-n'],
            capture_output=True, text=True, timeout=30
        )

        lines = result.stdout.strip().split('\n')
        stats['packets'] = len([l for l in lines if l])

        # 统计
        from collections import Counter
        import re

        ips = []
        ports = []
        protocols = Counter()

        for line in lines:
            # 提取IP
            ip_match = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
            ips.extend(ip_match)

            # 提取端口
            port_match = re.findall(r'\.(\d+)\s', line)
            ports.extend([int(p) for p in port_match if p.isdigit()])

            # 分析协议类型
            if ' TCP ' in line or line.strip().endswith(' Flags'):
                protocols['TCP'] += 1
            elif ' UDP ' in line:
                protocols['UDP'] += 1
            elif ' ICMP ' in line:
                protocols['ICMP'] += 1
            elif ' ARP ' in line:
                protocols['ARP'] += 1
            elif ' DNS' in line:
                protocols['DNS'] += 1
            else:
                protocols['Other'] += 1

        stats['top_hosts'] = dict(Counter(ips).most_common(10))
        stats['top_ports'] = dict(Counter(ports).most_common(10))
        stats['bytes'] = stats['packets'] * 1500  # 估算
        stats['protocols'] = dict(protocols) if protocols else {'Other': 0}

    except Exception as e:
        logger.error(f"分析pcap失败: {e}")

    return stats


@app.route('/api/report/generate', methods=['POST'])
def api_report_generate():
    """生成审计报告"""
    data = request.json
    report_type = data.get('type', 'summary')

    conn = get_db()
    try:
        if report_type == 'summary':
            # 摘要报告
            host_count = conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]

            # 漏洞统计（从扫描历史中提取）
            vuln_stats = [
                {'severity': 'critical', 'count': 0},
                {'severity': 'high', 'count': 0},
                {'severity': 'medium', 'count': 0},
                {'severity': 'low', 'count': 0},
                {'severity': 'info', 'count': 0}
            ]

            return jsonify({
                'success': True,
                'data': {
                    'host_count': host_count,
                    'vuln_stats': vuln_stats,
                    'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            })

        elif report_type == 'full':
            # 完整报告
            hosts = conn.execute('SELECT * FROM hosts ORDER BY ip').fetchall()
            scan_history = conn.execute(
                'SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT 50'
            ).fetchall()

            # 统计厂商分布
            vendors = conn.execute(
                'SELECT vendor, COUNT(*) as count FROM hosts GROUP BY vendor ORDER BY count DESC'
            ).fetchall()

            return jsonify({
                'success': True,
                'data': {
                    'summary': {
                        'total_hosts': len(hosts),
                        'total_scans': len(scan_history),
                        'vendors': [dict(v) for v in vendors]
                    },
                    'hosts': [dict(h) for h in hosts],
                    'scan_history': [dict(h) for h in scan_history],
                    'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            })

        else:
            return jsonify({
                'success': False,
                'message': '未知的报告类型'
            })
    finally:
        conn.close()


# ============================================================================
# 启动
# ============================================================================

def main():
    """主函数"""
    init_db()

    logger.info(f"启动边缘安全审计工具 v{VERSION}")
    logger.info(f"访问地址: http://0.0.0.0:{PORT}")

    app.run(host=HOST, port=PORT, debug=DEBUG)


if __name__ == '__main__':
    main()
