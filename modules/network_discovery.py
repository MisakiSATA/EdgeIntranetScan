# -*- coding: utf-8 -*-
"""
网络发现模块 - 简化版
使用nmap进行主机发现和端口扫描
"""

import subprocess
import logging
import xml.etree.ElementTree as ET
import sqlite3
import socket
from typing import List, Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# MAC地址厂商数据库
VENDOR_OUI_DB = {
    # 树莓派
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # VMware
    "00:0c:29": "VMware", "00:50:56": "VMware",
    # VirtualBox
    "08:00:27": "VirtualBox",
    # 小米
    "f4:8e:38": "Xiaomi", "34:ce:00": "Xiaomi", "78:11:dc": "Xiaomi",
    # 华为
    "f4:ec:38": "Huawei", "00:e0:fc": "Huawei", "8c:34:bd": "Huawei",
    # TP-Link
    "88:25:93": "TP-Link", "f0:b4:29": "TP-Link", "a0:f3:c1": "TP-Link",
    # 思科
    "00:1b:d5": "Cisco", "00:1e:14": "Cisco", "f0:29:29": "Cisco",
    # HPE
    "00:17:a4": "HPE", "3c:a8:2a": "HPE",
    # 戴尔
    "00:1b:21": "Dell", "00:1e:c9": "Dell",
    # 苹果
    "00:03:93": "Apple", "ac:87:a3": "Apple",
    # 三星
    "00:12:fb": "Samsung", "b4:8d:a6": "Samsung",
    # Intel
    "a0:36:9f": "Intel",
    # 网件
    "a4:17:31": "Netgear", "30:46:9a": "Netgear",
    # 友讯
    "00:05:5d": "D-Link", "1c:bd:5c": "D-Link",
    # 华硕
    "04:d4:c4": "Asus", "8c:dc:d4": "Asus",
    # 群晖
    "00:11:32": "Synology", "bc:5f:f4": "Synology",
}


class NetworkDiscovery:
    """网络发现器"""

    def __init__(self, network: str = "192.168.1.0/24", db_path: str = "data/audit.db"):
        self.network = network
        self.db_path = db_path
        self.hosts = []
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
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
        conn.commit()
        conn.close()

    def scan(self, top_ports: int = 100) -> List[Dict]:
        """
        扫描网段

        Args:
            top_ports: 扫描端口数量

        Returns:
            主机列表
        """
        logger.info(f"扫描网段: {self.network}")

        try:
            cmd = [
                "nmap",
                "-sn",  # 只ping扫描
                "-oX", "-",
                self.network
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )

            hosts = self._parse_hosts(result.stdout)

            # 对每个主机进行端口扫描
            for host in hosts:
                if host['status'] == 'up':
                    port_result = self._scan_ports(host['ip'], top_ports)
                    host['ports'] = port_result.get('ports', [])
                    host['open_ports'] = len(host['ports'])

            self.hosts = hosts
            self._save_to_db()

            return hosts

        except subprocess.TimeoutExpired:
            logger.error("扫描超时")
            return []
        except FileNotFoundError:
            logger.error("nmap未安装")
            return []
        except Exception as e:
            logger.error(f"扫描失败: {e}")
            return []

    def _parse_hosts(self, xml_output: str) -> List[Dict]:
        """解析主机列表"""
        hosts = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('.//host'):
                # 获取IP
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                ip = ip_elem.get('addr')

                # 获取MAC
                mac = ""
                mac_elem = host.find('.//address[@addrtype="mac"]')
                if mac_elem is not None:
                    mac = mac_elem.get('addr', '')

                # 获取主机状态
                status = "down"
                status_elem = host.find('status')
                if status_elem is not None:
                    status = status_elem.get('state', 'down')

                hosts.append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': self._resolve_hostname(ip),
                    'vendor': self._get_vendor(mac),
                    'status': status,
                    'ports': [],
                    'open_ports': 0
                })

        except ET.ParseError as e:
            logger.error(f"XML解析失败: {e}")

        return hosts

    def _scan_ports(self, ip: str, top_ports: int) -> Dict:
        """扫描单个主机的端口"""
        try:
            cmd = [
                "nmap",
                "-p", f"1-{top_ports}",
                "-oX", "-",
                ip
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            ports = []
            root = ET.fromstring(result.stdout)

            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    state_elem = port.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        port_id = port.get('portid')
                        service_elem = port.find('service')
                        service = service_elem.get('name', '') if service_elem is not None else ''

                        ports.append({
                            'port': int(port_id),
                            'service': service
                        })

            return {'ports': ports}

        except Exception as e:
            logger.error(f"端口扫描失败 {ip}: {e}")
            return {'ports': []}

    def _resolve_hostname(self, ip: str) -> str:
        """解析主机名"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""

    def _get_vendor(self, mac: str) -> str:
        """从MAC地址获取厂商"""
        if not mac:
            return ""
        oui = ":".join(mac.split(":")[:3]).lower()
        return VENDOR_OUI_DB.get(oui, "Unknown")

    def _save_to_db(self):
        """保存到数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for host in self.hosts:
            ports_str = ",".join(str(p['port']) for p in host.get('ports', []))

            cursor.execute("""
                INSERT OR REPLACE INTO hosts (ip, mac, hostname, vendor, status, ports, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                host['ip'],
                host.get('mac', ''),
                host.get('hostname', ''),
                host.get('vendor', ''),
                host['status'],
                ports_str,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))

        conn.commit()
        conn.close()

    def get_from_db(self) -> List[Dict]:
        """从数据库获取主机列表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
        rows = cursor.fetchall()

        conn.close()

        hosts = []
        for row in rows:
            ports = [int(p) for p in row[5].split(',') if p] if row[5] else []
            hosts.append({
                'ip': row[0],
                'mac': row[1],
                'hostname': row[2],
                'vendor': row[3],
                'status': row[4],
                'ports': ports,
                'open_ports': len(ports),
                'last_seen': row[6]
            })

        return hosts
