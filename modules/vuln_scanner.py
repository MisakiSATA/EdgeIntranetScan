# -*- coding: utf-8 -*-
"""
漏洞扫描模块
基础HTTP安全检查 + 常见漏洞检测
"""

import logging
import requests
import re
from typing import Dict, List
from datetime import datetime
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """漏洞扫描器"""

    def scan(self, target: str) -> Dict:
        """扫描目标漏洞"""
        logger.info(f"开始扫描: {target}")

        start_time = datetime.now()
        vulns = []

        # 确保目标有协议
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # 1. 基础HTTP检查
        vulns.extend(self._check_http_headers(target))

        # 2. 常见路径检查
        vulns.extend(self._check_common_paths(target))

        # 3. 注入检测
        vulns.extend(self._check_injections(target))

        # 4. 信息泄露检测
        vulns.extend(self._check_info_disclosure(target))

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

    def _check_common_paths(self, base_url: str) -> List[Dict]:
        """检查常见敏感路径"""
        vulns = []

        # 常见敏感路径
        sensitive_paths = {
            '/robots.txt': 'robots.txt文件',
            '/.git/config': 'Git配置泄露',
            '/.env': '环境变量文件',
            '/web.config': 'Web配置文件',
            '/README.md': 'README文件',
            '/.DS_Store': 'macOS文件',
            '/wp-admin/': 'WordPress后台',
            '/admin': '管理后台',
            '/phpmyadmin': 'phpMyAdmin',
            '/.svn/': 'SVN泄露',
            '/backup.sql': 'SQL备份文件',
        }

        for path, name in sensitive_paths.items():
            try:
                url = urljoin(base_url, path)
                response = requests.head(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    timeout=5,
                    allow_redirects=False
                )

                if response.status_code == 200:
                    vulns.append({
                        'name': f'敏感文件暴露: {name}',
                        'severity': 'MEDIUM' if 'admin' in path else 'LOW',
                        'description': f'{path} 可被访问',
                        'url': url
                    })
            except:
                pass

        return vulns

    def _check_injections(self, base_url: str) -> List[Dict]:
        """基础注入检测"""
        vulns = []

        # 检查常见参数
        parsed = urlparse(base_url)
        test_urls = []

        # 如果URL没有参数，添加测试参数
        if not parsed.query:
            base = base_url.rstrip('/')
            test_urls = [
                f'{base}/?id=1\'',
                f'{base}/?search=<script>alert(1)</script>',
                f'{base}/?file=../../../etc/passwd',
            ]
        else:
            # 在现有参数上追加测试
            sep = '&' if '?' in base_url else '?'
            test_urls = [
                f'{base_url}{sep}id=1\'',
                f'{base_url}{sep}test=<script>alert(1)</script>',
            ]

        # 测试GET参数注入
        for test_url in test_urls[:2]:  # 限制测试数量
            try:
                response = requests.get(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    timeout=5
                )

                content = response.text.lower()

                # SQL错误检测
                sql_errors = ['mysql_fetch', 'ora-', 'postgresql', 'you have an error in your sql syntax', 'warning: mysql']
                for error in sql_errors:
                    if error in content:
                        vulns.append({
                            'name': '可能的SQL注入',
                            'severity': 'HIGH',
                            'description': f'检测到SQL错误信息',
                            'url': test_url[:100]
                        })
                        break

                # XSS检测
                if '<script>alert(1)</script>' in content or 'alert(1)' in content:
                    vulns.append({
                        'name': '可能的XSS漏洞',
                        'severity': 'MEDIUM',
                        'description': '反射型XSS',
                        'url': test_url[:100]
                    })

            except:
                pass

        return vulns

    def _check_info_disclosure(self, url: str) -> List[Dict]:
        """信息泄露检测"""
        vulns = []

        try:
            response = requests.get(
                url,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=10
            )

            content = response.text

            # 检查注释中的敏感信息
            comments = re.findall(r'<!--.*?-->', content, re.DOTALL)
            for comment in comments:
                comment_lower = comment.lower()
                if any(word in comment_lower for word in ['password', 'api_key', 'secret', 'token', 'key']):
                    vulns.append({
                        'name': '注释中的敏感信息',
                        'severity': 'INFO',
                        'description': 'HTML注释可能包含敏感信息',
                        'url': url
                    })
                    break

            # 检查版本信息
            version_patterns = [
                r'jquery-[0-9.]+\.js',
                r'bootstrap-[0-9.]+\.js',
                r'vue-[0-9.]+\.js',
                r'react-[0-9.]+\.js',
            ]

            for pattern in version_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulns.append({
                        'name': 'JavaScript库版本暴露',
                        'severity': 'INFO',
                        'description': f'检测到可识别的库版本',
                        'url': url
                    })
                    break

        except:
            pass

        return vulns


# 测试
if __name__ == "__main__":
    import json
    scanner = VulnerabilityScanner()

    targets = [
        "http://testphp.vulnweb.com",
        "http://192.168.1.1"
    ]

    for target in targets:
        print(f"\n{'='*50}")
        print(f"扫描: {target}")
        print('='*50)
        result = scanner.scan(target)
        print(f"发现 {result['total']} 个问题")
        for v in result['vulnerabilities']:
            print(f"  [{v['severity']}] {v['name']}: {v['description'][:50]}")
