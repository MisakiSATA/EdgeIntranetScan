#!/bin/bash
# ============================================================
# 边缘安全审计工具 v2.0 - 一键部署与启动脚本
# 适用于 Armbian / Debian 系统
# ============================================================

cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $1"; [ -n "$2" ] && echo -e "${CYAN}    修复: ${NC}$2"; exit 1; }

echo ""
echo "========================================"
echo "  边缘安全审计工具 v2.0 - 一键部署"
echo "========================================"
echo ""

# ----------------------------------------------------------
# 0. 权限
# ----------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
    SUDO="sudo"
fi

# ----------------------------------------------------------
# 1. 系统依赖
# ----------------------------------------------------------
info "检查系统依赖..."

APT_UPDATED=false
apt_install() {
    [ "$APT_UPDATED" = false ] && { $SUDO apt update; APT_UPDATED=true; }
    if ! command -v "$1" &>/dev/null; then
        info "安装 $1 ..."
        $SUDO apt install -y "$1"
    fi
}

apt_install python3
apt_install nmap
apt_install tcpdump

# 确保 curl 或 wget 可用（后续下载需要）
if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    apt_install wget
fi

ok "nmap:    $(nmap --version 2>/dev/null | head -1)"
ok "tcpdump: $(tcpdump --version 2>/dev/null | head -1)"

# ----------------------------------------------------------
# 2. Python 虚拟环境
# ----------------------------------------------------------
VENV_DIR=".venv"
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)

# 如果已在 venv 中，直接用
if [ -n "$VIRTUAL_ENV" ]; then
    ok "已在虚拟环境中: $VIRTUAL_ENV"

# 如果 venv 已存在，直接激活
elif [ -f "$VENV_DIR/bin/activate" ]; then
    ok "虚拟环境已存在: $VENV_DIR"

else
    info "创建虚拟环境 (Python ${PY_VER:-?})..."

    VENV_OK=false

    # ── 方案 A: 尝试直接创建（ensurepip 可用时一步到位）──
    if [ "$VENV_OK" = false ]; then
        info "方案A: python3 -m venv $VENV_DIR"
        if python3 -m venv "$VENV_DIR" 2>/tmp/venv_err.log; then
            VENV_OK=true
        else
            cat /tmp/venv_err.log | head -3 | while read line; do warn "  $line"; done
        fi
        rm -f /tmp/venv_err.log
    fi

    # ── 方案 B: --without-pip 创建空壳 + get-pip.py 注入 ──
    # （Debian/Armbian 剥离了 ensurepip，方案 A 会报错，但 venv 模块本身还在）
    if [ "$VENV_OK" = false ]; then
        info "方案B: venv --without-pip + get-pip.py 注入"
        rm -rf "$VENV_DIR" 2>/dev/null
        if python3 -m venv --without-pip "$VENV_DIR" 2>/tmp/venv_err.log; then
            ok "  空壳 venv 创建成功"
            # 下载 get-pip.py 并注入到 venv 中
            info "  下载 pip ..."
            if command -v wget &>/dev/null; then
                wget -q --show-progress -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
            else
                curl -L --progress-bar -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
            fi
            "$VENV_DIR/bin/python3" /tmp/get-pip.py -q 2>/tmp/pip_err.log
            if [ -f "$VENV_DIR/bin/pip" ]; then
                VENV_OK=true
                ok "  pip 注入成功"
            else
                warn "  pip 注入失败:"
                cat /tmp/pip_err.log | head -3 | while read line; do warn "    $line"; done
                rm -rf "$VENV_DIR"
            fi
            rm -f /tmp/get-pip.py /tmp/pip_err.log
        else
            warn "  venv --without-pip 也失败:"
            cat /tmp/venv_err.log | head -3 | while read line; do warn "    $line"; done
            rm -rf "$VENV_DIR"
            rm -f /tmp/venv_err.log
        fi
    fi

    # ── 方案 C: get-pip.py 全局安装 + virtualenv ──
    if [ "$VENV_OK" = false ]; then
        info "方案C: 全局 get-pip.py + virtualenv"
        curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - 2>/dev/null \
            && python3 -m pip install virtualenv -q 2>/dev/null \
            && python3 -m virtualenv "$VENV_DIR" 2>/dev/null \
            && VENV_OK=true
    fi

    # ── 最终验证 ──
    if [ "$VENV_OK" = false ] || [ ! -f "$VENV_DIR/bin/activate" ]; then
        rm -rf "$VENV_DIR" 2>/dev/null
        fail "所有方案均失败，无法创建虚拟环境" \
             "1) sudo apt install python${PY_VER}-venv   (如果源里有)" \
             "2) 或重新安装 Python: sudo apt install --reinstall python${PY_VER}"
    fi

    ok "虚拟环境创建成功: $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# ----------------------------------------------------------
# 3. Python 依赖
# ----------------------------------------------------------
info "安装 Python 依赖..."

# 确保 venv 内有 pip
if ! command -v pip &>/dev/null; then
    warn "venv 内缺少 pip，尝试修复..."
    if command -v wget &>/dev/null; then
        wget -q -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
    else
        curl -sS -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
    fi
    python3 /tmp/get-pip.py -q
    rm -f /tmp/get-pip.py
fi

if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    pip install flask requests
fi

# 验证
python3 -c "import flask; import requests" 2>/dev/null \
    || fail "Flask 安装失败" "在虚拟环境中手动运行: pip install flask requests"

ok "Flask $(python3 -c 'import flask; print(flask.__version__)' 2>/dev/null)"

python3 -c "import netifaces" 2>/dev/null \
    || { info "安装 netifaces（可选）..."; pip install netifaces 2>/dev/null; }

# ----------------------------------------------------------
# 4. nuclei（可选）
# ----------------------------------------------------------
find_nuclei() {
    for p in "$HOME/go/bin/nuclei" "/usr/local/go/bin/nuclei"; do
        [ -f "$p" ] && [ -x "$p" ] && "$p" -version >/dev/null 2>&1 && echo "$p" && return
    done
    command -v nuclei 2>/dev/null && nuclei -version >/dev/null 2>&1 && echo "$(command -v nuclei)" && return
    echo ""
}

NUCLEI_BIN=$(find_nuclei)
if [ -n "$NUCLEI_BIN" ]; then
    ok "nuclei:  $(${NUCLEI_BIN} -version 2>/dev/null | head -1)"
else
    echo ""
    read -rp "$(echo -e "${YELLOW}是否安装 nuclei 漏洞扫描引擎？[y/N]:${NC} ")" ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then

        ARCH=$(uname -m)
        NUCLEI_INSTALL_DIR="$HOME/go/bin"
        mkdir -p "$NUCLEI_INSTALL_DIR"
        NUCLEI_OK=false

        # ── 方案 A: 下载预编译二进制（推荐，无需 Go，省空间）──
        info "下载 nuclei 预编译版..."
        case "$ARCH" in
            armv7l)  NUCLEI_ARCH="arm" ;;
            aarch64|arm64) NUCLEI_ARCH="arm64" ;;
            *)       NUCLEI_ARCH="$ARCH" ;;
        esac

        # 获取最新 release 版本号
        NUCLEI_VER=$(wget -qO- "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" 2>/dev/null \
            | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)

        if [ -n "$NUCLEI_VER" ]; then
            NUCLEI_ZIP="nuclei_${NUCLEI_VER#v}_linux_${NUCLEI_ARCH}.zip"
            NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/${NUCLEI_ZIP}"

            info "版本: ${NUCLEI_VER}, 架构: ${NUCLEI_ARCH}"
            info "下载 ${NUCLEI_ZIP} ..."

            if wget --progress=bar:force -O "/tmp/${NUCLEI_ZIP}" "$NUCLEI_URL" --timeout=60; then
                # 解压（确保 unzip 可用）
                if ! command -v unzip &>/dev/null; then
                    info "安装 unzip ..."
                    $SUDO apt install -y unzip
                fi
                rm -rf /tmp/nuclei_release
                mkdir -p /tmp/nuclei_release
                unzip -o -d /tmp/nuclei_release "/tmp/${NUCLEI_ZIP}"
                # 查找二进制文件（可能直接在根目录，也可能在子目录）
                NUCLEI_BIN_TMP=$(find /tmp/nuclei_release -name "nuclei" -type f 2>/dev/null | head -1)
                if [ -n "$NUCLEI_BIN_TMP" ]; then
                    chmod +x "$NUCLEI_BIN_TMP"
                    cp "$NUCLEI_BIN_TMP" "$NUCLEI_INSTALL_DIR/nuclei"
                    NUCLEI_OK=true
                    ok "nuclei 预编译版安装成功"
                else
                    warn "解压后未找到 nuclei 二进制文件"
                fi
                rm -rf "/tmp/${NUCLEI_ZIP}" /tmp/nuclei_release
            else
                warn "预编译版下载失败"
            fi
        else
            warn "无法获取最新版本号"
        fi

        # ── 方案 B: go install 编译（备用）──
        if [ "$NUCLEI_OK" = false ]; then
            echo ""
            warn "预编译版失败，尝试从源码编译（需要 Go 1.24+ 和约 2GB 临时空间）"
            read -rp "$(echo -e "${YELLOW}继续编译？可能因空间不足失败 [y/N]:${NC} ")" go_ans
            if [[ "$go_ans" =~ ^[Yy]$ ]]; then

                # 检查 Go 版本
                NEED_GO=false
                if command -v go &>/dev/null; then
                    GO_FULL=$(go version | grep -oP 'go[0-9]+\.[0-9]+' | head -1)
                    GO_MIN=${GO_FULL#*.}
                    info "系统 Go: ${GO_FULL}"
                    [ "$GO_MIN" -lt 24 ] 2>/dev/null && NEED_GO=true
                else
                    NEED_GO=true
                fi

                if [ "$NEED_GO" = true ]; then
                    case "$ARCH" in
                        armv7l)           GO_ARCH="armv6l" ;;
                        aarch64|arm64)    GO_ARCH="arm64" ;;
                        *)                GO_ARCH="$ARCH" ;;
                    esac
                    info "下载 Go 1.24.0 (${GO_ARCH}) ..."
                    wget -q --show-progress -O /tmp/go.tar.gz "https://go.dev/dl/go1.24.0.linux-${GO_ARCH}.tar.gz"
                    $SUDO rm -rf /usr/local/go
                    $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
                    rm -f /tmp/go.tar.gz
                    export PATH="/usr/local/go/bin:$PATH"
                    $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go 2>/dev/null
                    $SUDO ln -sf /usr/local/go/bin/go /usr/bin/go 2>/dev/null
                fi

                # 把临时目录指向 SD 卡（避免 tmpfs 空间不足）
                export GOTMPDIR="$HOME/tmp/go-build"
                mkdir -p "$GOTMPDIR"

                export PATH="$PATH:$HOME/go/bin"
                info "编译 nuclei（约 5-10 分钟）..."
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

                # 清理编译缓存释放空间
                go clean -cache 2>/dev/null
                rm -rf "$GOTMPDIR"
                info "已清理编译缓存"

                [ -f "$NUCLEI_INSTALL_DIR/nuclei" ] && NUCLEI_OK=true
            fi
        fi

        # ── 验证与模板更新 ──
        if [ "$NUCLEI_OK" = true ] && [ -f "$NUCLEI_INSTALL_DIR/nuclei" ]; then
            export PATH="$NUCLEI_INSTALL_DIR:$PATH"
            ok "nuclei $(nuclei -version 2>/dev/null | head -1)"
            info "下载漏洞模板..."
            nuclei -ut 2>&1 | tail -1
            ok "模板更新完成"
        else
            warn "nuclei 安装失败，漏洞扫描将仅执行 HTTP 头检查"
        fi
    else
        warn "跳过 nuclei，漏洞扫描将仅执行 HTTP 头检查"
    fi
fi

# ----------------------------------------------------------
# 5. 数据库
# ----------------------------------------------------------
mkdir -p data logs

# 确保当前用户对运行目录有写权限（防止之前用 sudo 运行残留的 root 权限文件）
[ "$(id -u)" -ne 0 ] && $SUDO chown -R "$(id -u):$(id -g)" data logs .venv 2>/dev/null

[ ! -f data/audit.db ] && {
    info "初始化数据库..."
    python3 -c "
import sqlite3
c = sqlite3.connect('data/audit.db')
c.executescript('''
    CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, vendor TEXT,
        status TEXT, ports TEXT, last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_type TEXT,
        target TEXT, result TEXT, scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS traffic_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT, interface TEXT, duration INTEGER,
        total_packets INTEGER DEFAULT 0, total_bytes INTEGER DEFAULT 0,
        protocols TEXT, top_hosts TEXT, top_ports TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
''')
c.commit(); c.close()"
    ok "数据库就绪"
}

# ----------------------------------------------------------
# 6. 启动
# ----------------------------------------------------------
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP="0.0.0.0"

echo ""
echo "========================================"
echo "  部署完成"
echo "========================================"
ok "Python:  $(python3 --version 2>&1)"
ok "Flask:   $(python3 -c 'import flask; print(flask.__version__)' 2>/dev/null)"
ok "nmap:    $(nmap --version 2>/dev/null | head -1)"
ok "tcpdump: $(tcpdump --version 2>/dev/null | head -1)"
NUCLEI_BIN=$(find_nuclei)
[ -n "$NUCLEI_BIN" ] && ok "nuclei:  $(${NUCLEI_BIN} -version 2>/dev/null | head -1)" || warn "nuclei:  未安装"

echo ""
info "访问地址: http://${IP}:8080"
info "按 Ctrl+C 停止服务"
echo ""

exec python3 app.py
