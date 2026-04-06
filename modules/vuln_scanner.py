# -*- coding: utf-8 -*-
"""
漏洞扫描模块
集成 nuclei 进行漏洞检测 + HTTP 安全头部检查
"""

import subprocess
import shutil
import os
import json
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# nuclei 模板默认存储路径
DEFAULT_NUCLEI_TEMPLATES_PATH = os.path.expanduser(
    '~/.config/nuclei/templates'
)


class VulnerabilityScanner:
    """漏洞扫描器 - 集成 nuclei"""

    def __init__(self, nuclei_path: str = "nuclei"):
        """
        初始化漏洞扫描器，自动检测 nuclei 可用性

        Args:
            nuclei_path: nuclei 可执行文件路径
        """
        self.nuclei_path = nuclei_path
        self._nuclei_available = False
        self._nuclei_version = ""
        self._templates_count = 0

        # 1. 查找 nuclei 可执行文件
        found_path = self._find_nuclei(nuclei_path)
        if found_path:
            self.nuclei_path = found_path
            self._nuclei_available = True
            logger.info(f"nuclei 找到: {found_path}")

            # 2. 获取 nuclei 版本（仅信息展示，不影响可用性）
            self._nuclei_version = self._get_nuclei_version()
            if self._nuclei_version:
                logger.info(f"nuclei 版本: {self._nuclei_version}")
            else:
                logger.warning("无法获取 nuclei 版本（不影响扫描功能）")

            # 3. 检查模板数量（这才是判断 nuclei 是否可用的关键）
            self._templates_count = self._count_templates()
            if self._templates_count > 0:
                logger.info(f"nuclei 模板数量: {self._templates_count}")
                self._nuclei_available = True
            else:
                logger.warning("nuclei 模板数量为 0，请运行 nuclei -ut 更新模板")
                self._nuclei_available = False
        else:
            logger.warning("nuclei 未找到，漏洞扫描将仅执行 HTTP 安全头检查")
            logger.warning("安装方法: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    def _find_nuclei(self, nuclei_path: str) -> Optional[str]:
        """
        查找 nuclei 可执行文件

        搜索顺序:
        1. 用户指定的路径
        2. 系统 PATH
        3. Go 默认安装路径
        """
        search_paths = [
            nuclei_path,
            os.path.expanduser('~/go/bin/nuclei'),
            '/usr/local/bin/nuclei',
        ]

        for path in search_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    def _get_nuclei_version(self) -> str:
        """获取 nuclei 版本号"""
        try:
            result = subprocess.run(
                [self.nuclei_path, '-version'],
                capture_output=True, text=True, timeout=10
            )
            # nuclei 输出可能在 stdout 或 stderr
            output = (result.stdout + "\n" + result.stderr).strip()
            if output:
                return output.split('\n')[0]
        except Exception as e:
            logger.debug(f"获取 nuclei 版本失败: {e}")
        return ""

    def _count_templates(self) -> int:
        """统计 nuclei 模板数量"""
        try:
            # 尝试 nuclei -tl 列出模板
            result = subprocess.run(
                [self.nuclei_path, '-tl'],
                capture_output=True, text=True, timeout=30
            )
            # nuclei -tl 输出每行一个模板路径
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
            if len(lines) > 0:
                return len(lines)

            # 备选：检查模板目录
            for tmpl_dir in [DEFAULT_NUCLEI_TEMPLATES_PATH]:
                if os.path.isdir(tmpl_dir):
                    count = sum(1 for _ in os.walk(tmpl_dir))
                    return max(count - 1, 0)  # 减去根目录本身
        except Exception as e:
            logger.debug(f"统计模板数量失败: {e}")
        return 0

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
        if self._nuclei_available and self._templates_count > 0:
            vulns.extend(self._scan_with_nuclei(target))
        elif self._nuclei_available and self._templates_count == 0:
            # nuclei 可用但没有模板
            vulns.append({
                'name': 'nuclei 模板未安装',
                'severity': 'INFO',
                'description': 'nuclei 已安装但模板库为空，请运行: nuclei -ut 下载漏洞模板',
                'url': target
            })
        elif not self._nuclei_available:
            vulns.append({
                'name': 'nuclei 未安装',
                'severity': 'INFO',
                'description': '未检测到 nuclei。安装方法: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  '
                               '然后运行 nuclei -ut 更新模板',
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
            'scan_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'nuclei_available': self._nuclei_available,
            'nuclei_version': self._nuclei_version,
            'templates_count': self._templates_count,
        }

    def _scan_with_nuclei(self, target: str) -> List[Dict]:
        """
        使用 nuclei 扫描目标漏洞

        Args:
            target: 目标URL

        Returns:
            漏洞列表
        """
        logger.info(f"使用 nuclei 扫描: {target} (模板数: {self._templates_count})")
        vulns = []

        cmd = [
            self.nuclei_path,
            "-u", target,
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "10",
            "-retries", "1",
            "-c", "50",  # 并发模板数，避免资源耗尽
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # 记录 nuclei 的 stderr 用于调试
            if result.stderr:
                stderr_lines = result.stderr.strip().split('\n')
                for line in stderr_lines:
                    line_lower = line.lower()
                    # 只记录有意义的警告和错误
                    if any(kw in line_lower for kw in ['error', 'warn', 'fail', 'cannot', 'unable']):
                        logger.warning(f"nuclei: {line.strip()[:200]}")

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
            vulns.append({
                'name': '扫描超时',
                'severity': 'INFO',
                'description': 'nuclei 扫描超过300秒被强制终止，可尝试缩小扫描范围',
                'url': target
            })
        except Exception as e:
            logger.error(f"nuclei 扫描失败: {e}")
            vulns.append({
                'name': '扫描异常',
                'severity': 'INFO',
                'description': f'nuclei 执行出错: {str(e)[:100]}',
                'url': target
            })

        return vulns

    def _parse_nuclei_line(self, line: str) -> Dict:
        """解析 nuclei 单行 JSON 输出"""
        try:
            data = json.loads(line)

            info = data.get('info', {})
            name = info.get('name', 'Unknown')
            severity = info.get('severity', 'info').upper()
            description = info.get('description', '')
            matched_at = data.get('matched-at', '')
            template_id = data.get('template-id', '')
            tags = info.get('tags', [])

            if not description and tags:
                description = f"Tags: {', '.join(tags)}"

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

        except (json.JSONDecodeError, KeyError, TypeError):
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

            if 'server' in headers:
                vulns.append({
                    'name': '服务器信息泄露',
                    'severity': 'INFO',
                    'description': f'Server: {headers["server"]}',
                    'url': url
                })

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

    print(f"nuclei 可用: {scanner._nuclei_available}")
    print(f"nuclei 版本: {scanner._nuclei_version}")
    print(f"模板数量: {scanner._templates_count}")

    if scanner._nuclei_available:
        targets = ["http://testphp.vulnweb.com"]
        for target in targets:
            print(f"\n{'='*50}")
            print(f"扫描: {target}")
            result = scanner.scan(target)
            print(f"发现 {result['total']} 个问题")
            for v in result['vulnerabilities']:
                print(f"  [{v['severity']}] {v['name']}: {v['description'][:80]}")
    else:
        print("nuclei 不可用，仅执行 HTTP 头检查")
        result = scanner.scan("http://127.0.0.1")
        for v in result['vulnerabilities']:
            print(f"  [{v['severity']}] {v['name']}")
