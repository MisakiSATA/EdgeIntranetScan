# -*- coding: utf-8 -*-
"""
端口扫描模块 - 简化版
使用nmap进行端口扫描
"""

import subprocess
import json
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PortScanner:
    """端口扫描器"""

    # 高风险端口
    HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900}

    def __init__(self):
        self.nmap_path = "nmap"

    def scan(self, target: str, ports: str = "1-1000") -> Dict:
        """
        扫描目标端口

        Args:
            target: 目标IP
            ports: 端口范围，如 "1-1000" 或 "22,80,443"

        Returns:
            扫描结果字典
        """
        logger.info(f"扫描 {target} 端口 {ports}")

        start_time = datetime.now()

        try:
            # 使用nmap XML输出，更可靠
            cmd = [
                self.nmap_path,
                "-p", ports,
                "-sV",           # 服务版本检测
                "-T4",           # 快速扫描
                "-oX", "-",      # XML输出到stdout
                target
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # 解析XML结果
            ports_info = self._parse_xml(result.stdout)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            return {
                'success': True,
                'target': target,
                'ports': ports_info,
                'total': len(ports_info),
                'duration': round(duration, 2),
                'scan_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
            }

        except subprocess.TimeoutExpired:
            logger.error("扫描超时")
            return {
                'success': False,
                'target': target,
                'error': '扫描超时',
                'ports': [],
                'total': 0
            }
        except FileNotFoundError:
            logger.error("nmap未安装")
            return {
                'success': False,
                'target': target,
                'error': 'nmap未安装',
                'ports': [],
                'total': 0
            }
        except Exception as e:
            logger.error(f"扫描失败: {e}")
            return {
                'success': False,
                'target': target,
                'error': str(e),
                'ports': [],
                'total': 0
            }

    def _parse_xml(self, xml_output: str) -> List[Dict]:
        """解析nmap XML输出"""
        ports_list = []

        try:
            root = ET.fromstring(xml_output)

            # 查找host节点
            for host in root.findall('.//host'):
                # 检查主机状态
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                # 查找端口
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol', 'tcp')

                    state_elem = port.find('state')
                    if state_elem is None:
                        continue
                    state = state_elem.get('state')

                    # 只记录开放的端口
                    if state != 'open':
                        continue

                    # 获取服务信息
                    service = ""
                    version = ""
                    service_elem = port.find('service')
                    if service_elem is not None:
                        service = service_elem.get('name', '')
                        version = service_elem.get('version', '')
                        if not version:
                            version = service_elem.get('product', '')

                    # 评估风险
                    port_num = int(port_id)
                    if port_num in self.HIGH_RISK_PORTS:
                        risk = 'HIGH'
                    elif port_num in [22, 80, 8080]:
                        risk = 'MEDIUM'
                    else:
                        risk = 'LOW'

                    ports_list.append({
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version,
                        'risk': risk
                    })

        except ET.ParseError as e:
            logger.error(f"XML解析失败: {e}")
        except Exception as e:
            logger.error(f"解析错误: {e}")

        return ports_list


# 测试
if __name__ == "__main__":
    scanner = PortScanner()
    result = scanner.scan("127.0.0.1", "22,80,443,8080")
    print(json.dumps(result, indent=2, ensure_ascii=False))
