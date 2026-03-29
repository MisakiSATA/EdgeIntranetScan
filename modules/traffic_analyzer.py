# -*- coding: utf-8 -*-
"""
网络流量分析模块
使用 tcpdump 进行流量捕获和分析，实现流量统计和异常检测
"""

import subprocess
import re
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from collections import Counter
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TrafficStats:
    """流量统计数据结构"""
    timestamp: float
    total_packets: int
    total_bytes: int
    duration: int
    protocols: Dict[str, int]
    top_hosts: List[Tuple[str, int]]
    top_ports: List[Tuple[int, int]]
    capture_file: str = ""

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'duration': self.duration,
            'protocols': self.protocols,
            'top_hosts': [{'host': h, 'count': c} for h, c in self.top_hosts],
            'top_ports': [{'port': p, 'count': c} for p, c in self.top_ports],
            'capture_file': self.capture_file
        }


class TrafficAnalyzer:
    """网络流量分析器类"""

    # 常见协议端口映射
    PROTOCOL_PORTS = {
        'HTTP': 80,
        'HTTPS': 443,
        'SSH': 22,
        'FTP': 21,
        'DNS': 53,
        'SMTP': 25,
        'POP3': 110,
        'IMAP': 143,
        'MySQL': 3306,
        'RDP': 3389,
    }

    def __init__(
        self,
        interface: str = "eth0",
        capture_dir: str = "data/captures",
        tcpdump_path: str = "tcpdump"
    ):
        """
        初始化流量分析器

        Args:
            interface: 网络接口名称
            capture_dir: 抓包文件保存目录
            tcpdump_path: tcpdump 可执行文件路径
        """
        self.interface = interface
        self.capture_dir = capture_dir
        self.tcpdump_path = tcpdump_path
        self.capture_process: Optional[subprocess.Popen] = None
        self.is_capturing = False

        # 确保抓包目录存在
        os.makedirs(capture_dir, exist_ok=True)

    def start_capture(
        self,
        duration: int = 60,
        packet_count: int = 10000,
        filter: Optional[str] = None
    ) -> str:
        """
        开始抓包

        Args:
            duration: 抓包持续时间（秒），0 表示不限时
            packet_count: 最大抓包数量
            filter: BPF 过滤表达式

        Returns:
            抓包文件路径
        """
        if self.is_capturing:
            logger.warning("抓包已在进行中")
            return ""

        # 生成抓包文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        capture_file = os.path.join(self.capture_dir, f"capture_{timestamp}.pcap")

        # 构建 tcpdump 命令
        cmd = [
            self.tcpdump_path,
            "-i", self.interface,
            "-w", capture_file,
            "-c", str(packet_count)
        ]

        # 添加过滤规则
        if filter:
            cmd.extend(filter.split())

        logger.info(f"开始抓包: 接口={self.interface}, 文件={capture_file}")
        logger.debug(f"执行命令: {' '.join(cmd)}")

        try:
            # 启动抓包进程
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.is_capturing = True

            # 如果设置了持续时间，启动定时器自动停止
            if duration > 0:
                stop_timer = threading.Timer(duration, self.stop_capture)
                stop_timer.daemon = True
                stop_timer.start()

            return capture_file

        except FileNotFoundError:
            logger.error(f"tcpdump 未找到: {self.tcpdump_path}")
            return ""
        except Exception as e:
            logger.error(f"启动抓包失败: {e}")
            return ""

    def stop_capture(self):
        """停止抓包"""
        if not self.is_capturing:
            return

        logger.info("停止抓包")

        if self.capture_process:
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()

        self.is_capturing = False

    def analyze_capture(self, pcap_file: Optional[str] = None) -> TrafficStats:
        """
        分析抓包文件

        Args:
            pcap_file: 抓包文件路径，为 None 时分析最近一次抓包

        Returns:
            流量统计信息
        """
        if pcap_file is None:
            # 获取最新的抓包文件
            files = [f for f in os.listdir(self.capture_dir) if f.endswith('.pcap')]
            if not files:
                logger.warning("没有找到抓包文件")
                return self._empty_stats()
            pcap_file = os.path.join(self.capture_dir, sorted(files)[-1])

        if not os.path.exists(pcap_file):
            logger.error(f"抓包文件不存在: {pcap_file}")
            return self._empty_stats()

        logger.info(f"分析抓包文件: {pcap_file}")

        try:
            # 使用 tcpdump 分析
            stats = self._analyze_with_tcpdump(pcap_file)

            # 尝试使用 nDPI 进行深度分析（可选）
            protocols = self._analyze_protocols(pcap_file)

            return TrafficStats(
                timestamp=time.time(),
                total_packets=stats['packets'],
                total_bytes=stats['bytes'],
                duration=stats['duration'],
                protocols=protocols,
                top_hosts=stats['top_hosts'],
                top_ports=stats['top_ports'],
                capture_file=pcap_file
            )

        except Exception as e:
            logger.error(f"分析抓包文件失败: {e}")
            return self._empty_stats()

    def _analyze_with_tcpdump(self, pcap_file: str) -> Dict:
        """使用 tcpdump 分析抓包文件"""
        try:
            # 读取抓包内容
            cmd = [self.tcpdump_path, "-r", pcap_file, "-n"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            lines = result.stdout.strip().split('\n')
            packet_count = len([l for l in lines if l.strip()])

            # 统计主机和端口
            hosts = Counter()
            ports = Counter()

            # IP:端口 模式
            ip_port_pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+)'

            for line in lines:
                matches = re.findall(ip_port_pattern, line)
                for ip, port in matches:
                    hosts[ip] += 1
                    try:
                        ports[int(port)] += 1
                    except ValueError:
                        pass

            # 估算字节数（平均每包1500字节）
            bytes_estimate = packet_count * 1500

            return {
                'packets': packet_count,
                'bytes': bytes_estimate,
                'duration': 0,  # 需要从抓包文件读取实际时间
                'top_hosts': hosts.most_common(10),
                'top_ports': ports.most_common(10)
            }

        except subprocess.TimeoutExpired:
            logger.error("tcpdump 分析超时")
            return {'packets': 0, 'bytes': 0, 'duration': 0, 'top_hosts': [], 'top_ports': []}
        except Exception as e:
            logger.error(f"tcpdump 分析失败: {e}")
            return {'packets': 0, 'bytes': 0, 'duration': 0, 'top_hosts': [], 'top_ports': []}

    def _analyze_protocols(self, pcap_file: str) -> Dict[str, int]:
        """分析协议分布"""
        try:
            # 使用 tcpdump 统计端口分布来估算协议
            cmd = [self.tcpdump_path, "-r", pcap_file, "-n"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # 端口计数
            port_counter = Counter()

            ip_port_pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+)'
            for line in result.stdout.split('\n'):
                matches = re.findall(ip_port_pattern, line)
                for ip, port in matches:
                    try:
                        port_counter[int(port)] += 1
                    except ValueError:
                        pass

            # 根据端口估算协议
            protocols = Counter()
            port_to_protocol = {v: k for k, v in self.PROTOCOL_PORTS.items()}

            for port, count in port_counter.items():
                protocol = port_to_protocol.get(port, 'Other')
                protocols[protocol] += count

            return dict(protocols)

        except Exception as e:
            logger.debug(f"协议分析失败: {e}")
            return {'Other': 0}

    def detect_anomalies(
        self,
        current_stats: TrafficStats,
        baseline_stats: Optional[TrafficStats] = None
    ) -> List[str]:
        """
        检测流量异常

        Args:
            current_stats: 当前流量统计
            baseline_stats: 基线流量统计

        Returns:
            异常信息列表
        """
        anomalies = []

        if baseline_stats is None:
            logger.warning("未提供基线数据，跳过异常检测")
            return anomalies

        # 流量异常检测
        if current_stats.total_bytes > baseline_stats.total_bytes * 2:
            anomalies.append(
                f"流量异常: 当前流量 {current_stats.total_bytes:,} 字节，"
                f"约为基线 {baseline_stats.total_bytes:,} 字节的 "
                f"{current_stats.total_bytes / max(baseline_stats.total_bytes, 1):.1f} 倍"
            )

        # 新主机检测
        baseline_hosts = {h[0] for h in baseline_stats.top_hosts}
        current_hosts = {h[0] for h in current_stats.top_hosts}
        new_hosts = current_hosts - baseline_hosts

        if new_hosts:
            anomalies.append(f"发现新主机: {', '.join(list(new_hosts)[:5])}")

        # 新端口检测
        baseline_ports = {p[0] for p in baseline_stats.top_ports}
        current_ports = {p[0] for p in current_stats.top_ports}
        new_ports = current_ports - baseline_ports

        if new_ports:
            port_list = list(new_ports)[:5]
            anomalies.append(f"发现新端口: {', '.join(map(str, port_list))}")

        # 协议分布变化检测
        for protocol, count in current_stats.protocols.items():
            baseline_count = baseline_stats.protocols.get(protocol, 0)
            if baseline_count > 0 and count > baseline_count * 3:
                anomalies.append(
                    f"{protocol} 协议流量激增: 当前 {count:,}，基线 {baseline_count:,}"
                )

        return anomalies

    def get_interface_list(self) -> List[str]:
        """
        获取可用的网络接口列表

        Returns:
            接口名称列表
        """
        try:
            # Linux 下读取 /proc/net/dev
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()[2:]  # 跳过前两行标题

            interfaces = []
            for line in lines:
                parts = line.split(':')
                if len(parts) > 1:
                    interface = parts[0].strip()
                    if interface and interface != 'lo':
                        interfaces.append(interface)

            return interfaces

        except Exception as e:
            logger.error(f"获取网络接口失败: {e}")
            return ['eth0', 'wlan0']

    def _empty_stats(self) -> TrafficStats:
        """返回空的统计数据"""
        return TrafficStats(
            timestamp=time.time(),
            total_packets=0,
            total_bytes=0,
            duration=0,
            protocols={},
            top_hosts=[],
            top_ports=[]
        )

    def export_report(self, stats: TrafficStats, format: str = "text") -> str:
        """
        导出流量分析报告

        Args:
            stats: 流量统计数据
            format: 报告格式 (text, json)

        Returns:
            报告内容
        """
        if format == "json":
            return json.dumps(stats.to_dict(), indent=2, ensure_ascii=False)

        # 文本格式报告
        report_lines = [
            "=" * 80,
            "网络流量分析报告",
            "=" * 80,
            "",
            f"分析时间: {stats.to_dict()['datetime']}",
            f"抓包文件: {stats.capture_file}",
            "",
            "流量统计:",
            f"  总数据包: {stats.total_packets:,}",
            f"  总字节数: {stats.total_bytes:,}",
            f"  持续时间: {stats.duration} 秒",
            "",
            "协议分布:",
        ]

        for protocol, count in sorted(stats.protocols.items(), key=lambda x: -x[1]):
            percentage = (count / max(stats.total_packets, 1)) * 100
            report_lines.append(f"  {protocol}: {count:,} ({percentage:.1f}%)")

        report_lines.extend([
            "",
            "最活跃的主机 (Top 10):",
        ])

        for i, (host, count) in enumerate(stats.top_hosts[:10], 1):
            report_lines.append(f"  {i}. {host}: {count} 个数据包")

        report_lines.extend([
            "",
            "最常用的端口 (Top 10):",
        ])

        for i, (port, count) in enumerate(stats.top_ports[:10], 1):
            protocol = self._port_to_protocol(port)
            report_lines.append(f"  {i}. {port} ({protocol}): {count} 个数据包")

        report_lines.append("")
        return "\n".join(report_lines)

    def _port_to_protocol(self, port: int) -> str:
        """根据端口号获取协议名"""
        for protocol, proto_port in self.PROTOCOL_PORTS.items():
            if port == proto_port:
                return protocol
        return "Unknown"


# 测试代码
if __name__ == "__main__":
    import sys

    # 创建分析器
    analyzer = TrafficAnalyzer(interface="eth0")

    # 获取可用接口
    interfaces = analyzer.get_interface_list()
    print(f"可用网络接口: {', '.join(interfaces)}")

    # 开始抓包（30秒或1000个包）
    print("开始抓包（30秒）...")
    capture_file = analyzer.start_capture(duration=30, packet_count=1000)

    if capture_file:
        print(f"抓包文件: {capture_file}")

        # 等待抓包完成
        time.sleep(31)

        # 分析抓包
        print("分析抓包...")
        stats = analyzer.analyze_capture(capture_file)

        # 打印统计
        print(f"\n流量统计:")
        print(f"  数据包: {stats.total_packets}")
        print(f"  字节数: {stats.total_bytes:,}")
        print(f"  协议: {stats.protocols}")

        # 导出报告
        print("\n" + analyzer.export_report(stats))
    else:
        print("抓包启动失败")
