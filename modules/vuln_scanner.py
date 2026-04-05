# -*- coding: utf-8 -*-
"""
漏洞扫描模块
集成 nuclei 进行漏洞检测 + HTTP 安全头部检查
"""

import subprocess
import shutil
import json
import logging
import requests
import re
from typing import Dict, List
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """漏洞扫描器 - 集成 nuclei"""

    def __init__(self, nuclei_path: str = "nuclei"):
        """
        初始化漏洞扫描器

        Args:
            nuclei_path: nuclei 可执行文件路径
        """
        self.nuclei_path = nuclei_path
        self._nuclei_available = shutil.which(nuclei_path) is not None

        if not self._nuclei_available:
            logger.warning("nuclei 未找到，漏洞扫描将仅执行 HTTP 安全头检查")

    def scan(self, target: str) -> Dict:
        """
        扫描目标漏洞

        Args:
            target: 目标URL或IP

        Returns:
            扫描结果字典
        """
        logger.info(f"开始扫描: {target}")

        start_time = datetime.now()
        vulns = []

        # 确保目标有协议
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # 1. HTTP 安全头检查（始终执行，快速）
        vulns.extend(self._check_http_headers(target))

        # 2. nuclei 漏洞扫描（核心）
        if self._nuclei_available:
            vulns.extend(self._scan_with_nuclei(target))
        else:
            vulns.append({
                'name': 'nuclei 未安装',
                'severity': 'INFO',
                'description': '未检测到 nuclei，仅执行了 HTTP 安全头检查。'
                               '请运行: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
                'url': target
            })

        # 统计
        critical = sum(1 for v in vulns if v['severity'] == 'CRITICAL')
        high = sum(1 for v in vulns if v['severity'] == 'HIGH')
        medium = sum(1 for v in vulns if v['severity'] == 'MEDIUM')
        low = sum(1 for v in vulns if v['severity'] == 'LOW')
        info = sum(1 for v in vulns if v['severity'] == 'INFO')

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return {
            'success': True,
            'target': target,
            'vulnerabilities': vulns,
            'total': len(vulns),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info,
            'duration': round(duration, 2),
            'scan_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
        }

    def _scan_with_nuclei(self, target: str) -> List[Dict]:
        """
        使用 nuclei 扫描目标漏洞

        Args:
            target: 目标URL

        Returns:
            漏洞列表
        """
        logger.info(f"使用 nuclei 扫描: {target}")
        vulns = []

        cmd = [
            self.nuclei_path,
            "-u", target,
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "10",
            "-retries", "1"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # nuclei 的 JSON 输出是每行一个 JSON 对象
            # 错误信息输出到 stderr
            if result.stderr:
                stderr_lower = result.stderr.lower()
                if 'error' in stderr_lower:
                    logger.warning(f"nuclei 警告: {result.stderr.strip()[:200]}")

            # 解析 stdout 中的 JSON 行
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                vuln = self._parse_nuclei_line(line)
                if vuln:
                    vulns.append(vuln)

            logger.info(f"nuclei 扫描完成，发现 {len(vulns)} 个漏洞")

        except subprocess.TimeoutExpired:
            logger.error("nuclei 扫描超时（300秒）")
        except FileNotFoundError:
            logger.error("nuclei 未找到")
            self._nuclei_available = False
        except Exception as e:
            logger.error(f"nuclei 扫描失败: {e}")

        return vulns

    def _parse_nuclei_line(self, line: str) -> Dict:
        """
        解析 nuclei 单行 JSON 输出

        nuclei 输出格式:
        {
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "high",
                "description": "...",
                "tags": ["cve", "apache", "lfi"]
            },
            "matched-at": "http://target/cgi-bin/...",
            "host": "http://target",
            "type": "http"
        }
        """
        try:
            data = json.loads(line)

            info = data.get('info', {})
            name = info.get('name', 'Unknown')
            severity = info.get('severity', 'info').upper()
            description = info.get('description', '')
            matched_at = data.get('matched-at', '')
            template_id = data.get('template-id', '')
            tags = info.get('tags', [])

            # 如果没有描述，用 tags 组合一个
            if not description and tags:
                description = f"Tags: {', '.join(tags)}"

            # 构建显示名称
            display_name = name
            if template_id:
                display_name = f"[{template_id}] {name}"

            return {
                'name': display_name,
                'severity': severity,
                'description': description[:200] if description else '无详细描述',
                'url': matched_at or data.get('host', ''),
                'template_id': template_id,
                'tags': tags
            }

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.debug(f"解析 nuclei 输出失败: {e}")
            return None

    def _check_http_headers(self, url: str) -> List[Dict]:
        """检查HTTP安全头部"""
        vulns = []

        try:
            response = requests.get(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (X11; Linux; EdgeAuditTool)'},
                timeout=10,
                allow_redirects=True
            )

            vulns.append({
                'name': '目标可达',
                'severity': 'INFO',
                'description': f'HTTP {response.status_code} - {response.reason}',
                'url': url
            })

            headers = response.headers
            header_keys = [k.lower() for k in headers.keys()]

            # 安全头部检查
            if 'x-frame-options' not in header_keys:
                vulns.append({
                    'name': '缺少 X-Frame-Options',
                    'severity': 'LOW',
                    'description': '可能受到点击劫持攻击',
                    'url': url
                })

            if 'content-security-policy' not in header_keys:
                vulns.append({
                    'name': '缺少 Content-Security-Policy',
                    'severity': 'LOW',
                    'description': '可能受到XSS攻击',
                    'url': url
                })

            if 'strict-transport-security' not in header_keys and url.startswith('https://'):
                vulns.append({
                    'name': '缺少 HSTS',
                    'severity': 'INFO',
                    'description': '建议启用HTTP严格传输安全',
                    'url': url
                })

            # 服务器信息泄露
            if 'server' in headers:
                vulns.append({
                    'name': '服务器信息泄露',
                    'severity': 'INFO',
                    'description': f'Server: {headers["server"]}',
                    'url': url
                })

            # 检查X-Powered-By
            if 'x-powered-by' in headers:
                vulns.append({
                    'name': '技术栈泄露',
                    'severity': 'INFO',
                    'description': f'X-Powered-By: {headers["x-powered-by"]}',
                    'url': url
                })

        except requests.exceptions.Timeout:
            vulns.append({
                'name': '连接超时',
                'severity': 'INFO',
                'description': '请求超时(10秒)',
                'url': url
            })
        except requests.exceptions.ConnectionError as e:
            vulns.append({
                'name': '连接失败',
                'severity': 'INFO',
                'description': f'无法连接: {str(e.reason)[:50]}',
                'url': url
            })
        except Exception as e:
            vulns.append({
                'name': '扫描错误',
                'severity': 'INFO',
                'description': f'{type(e).__name__}',
                'url': url
            })

        return vulns


# 测试
if __name__ == "__main__":
    scanner = VulnerabilityScanner()

    targets = [
        "http://testphp.vulnweb.com",
    ]

    for target in targets:
        print(f"\n{'='*50}")
        print(f"扫描: {target}")
        print('='*50)
        result = scanner.scan(target)
        print(f"发现 {result['total']} 个问题 (nuclei 可用: {scanner._nuclei_available})")
        for v in result['vulnerabilities']:
            print(f"  [{v['severity']}] {v['name']}: {v['description'][:80]}")
