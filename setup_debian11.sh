#!/bin/bash

# =============================================================================
# 脚本名称: Debian 11 VPS 初始化全能脚本
# 功能: SSH加固 / UFW / Fail2Ban / BBR / NTP / 日志权限 / 时区 / Swap
# 说明: 适用于 Debian 11 全新系统安装后的首次初始化
# =============================================================================

set -Eeuo pipefail

trap 'echo -e "\033[0;31m[ERROR]\033[0m 脚本执行失败: 行号 ${LINENO}, 命令: ${BASH_COMMAND}"' ERR

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 默认 SSH 公钥
DEFAULT_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvyH3RGNA/b9OuBLnHIpzmFIOQuWSpSt2bdgyPjoujE admin@gmail.com"

echo -e "${GREEN}=== 开始执行 Debian 11 初始化配置 ===${NC}"

# =======================================================
# 1. 权限检查
# =======================================================
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}错误: 请使用 root 权限运行此脚本!${NC}"
  exit 1
fi

# =======================================================
# 2. 系统版本检查
# =======================================================
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "11" ]; then
    echo -e "${YELLOW}警告: 当前系统不是 Debian 11，检测到: ${PRETTY_NAME:-未知系统}${NC}"
    read -r -p "是否继续执行? (y/n, 默认 n): " CONTINUE_ANYWAY
    CONTINUE_ANYWAY=${CONTINUE_ANYWAY:-n}
    if [[ ! "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]]; then
      echo -e "${RED}已取消执行。${NC}"
      exit 1
    fi
  fi
fi

# =======================================================
# 3. 更新系统与安装依赖
# =======================================================
echo -e "${YELLOW}>> [1/9] 更新系统与安装依赖...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y curl wget git vim ufw fail2ban chrony rsyslog openssh-server python3-systemd ca-certificates

# =======================================================
# 4. 日志环境初始化
# =======================================================
echo -e "${YELLOW}>> [2/9] 初始化系统日志环境...${NC}"

systemctl enable --now rsyslog >/dev/null 2>&1
sleep 1

LOG_FILE="/var/log/auth.log"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
chown root:adm "$LOG_FILE"
echo -e "${GREEN}日志权限已修正为 640 (root:adm)。${NC}"

# =======================================================
# 5. SSH 配置
# =======================================================
echo -e "${YELLOW}>> [3/9] 配置 SSH 安全选项...${NC}"

echo -e "${CYAN}请设置 SSH 登录公钥:${NC}"
echo -e "请直接粘贴您的公钥字符串 (以 ssh-xxx 开头)"
read -r -p "请输入公钥 (直接回车则使用内置默认公钥): " INPUT_SSH_KEY

if [ -z "$INPUT_SSH_KEY" ]; then
    FINAL_SSH_KEY="$DEFAULT_SSH_KEY"
    echo -e "${GREEN}未检测到输入，将使用默认公钥。${NC}"
else
    FINAL_SSH_KEY="$INPUT_SSH_KEY"
    echo -e "${GREEN}已捕获自定义公钥。${NC}"
fi

mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
grep -qxF "$FINAL_SSH_KEY" /root/.ssh/authorized_keys || echo "$FINAL_SSH_KEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo -e "${GREEN}SSH 公钥已写入 authorized_keys。${NC}"

mkdir -p /etc/ssh/sshd_config.d

echo -e "${CYAN}--- SSH 端口设置 ---${NC}"
CURRENT_SSH_PORT=22
echo -e "当前 SSH 监听端口默认为: $CURRENT_SSH_PORT"

while true; do
    read -r -p "请输入新的 SSH 端口 (1024-65535，直接回车则保持 $CURRENT_SSH_PORT 不变): " NEW_SSH_PORT

    if [ -z "$NEW_SSH_PORT" ]; then
        FINAL_SSH_PORT=$CURRENT_SSH_PORT
        echo -e "${GREEN}SSH 端口保持为 $FINAL_SSH_PORT。${NC}"
        break
    fi

    if [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_SSH_PORT" -ge 1024 ] && [ "$NEW_SSH_PORT" -le 65535 ]; then
        FINAL_SSH_PORT=$NEW_SSH_PORT
        echo -e "${GREEN}SSH 端口将设置为 $FINAL_SSH_PORT。${NC}"
        break
    else
        echo -e "${RED}输入错误！请输入 1024 到 65535 之间的纯数字。${NC}"
    fi
done

cat > /etc/ssh/sshd_config.d/99-vps-init.conf <<EOF
Port $FINAL_SSH_PORT
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
UseDNS no
X11Forwarding no
PermitRootLogin prohibit-password
AuthorizedKeysFile .ssh/authorized_keys
EOF

sshd -t
echo -e "${GREEN}SSH 安全配置已更新并通过校验。${NC}"

UFW_SSH_PORT=$FINAL_SSH_PORT

# =======================================================
# 6. 时区设置
# =======================================================
echo -e "${YELLOW}>> [4/9] 配置系统时区...${NC}"
read -r -p "请输入系统时区 (回车默认 Asia/Shanghai): " INPUT_TZ
SYS_TZ=${INPUT_TZ:-Asia/Shanghai}
timedatectl set-timezone "$SYS_TZ"
echo -e "${GREEN}系统时区已设置为: $SYS_TZ${NC}"

# =======================================================
# 7. NTP 时间同步 (Chrony + Cloudflare)
# =======================================================
echo -e "${YELLOW}>> [5/9] 配置 NTP 时间同步 (Chrony)...${NC}"

CHRONY_CONF="/etc/chrony/chrony.conf"
cp "$CHRONY_CONF" "${CHRONY_CONF}.bak.$(date +%F_%H-%M-%S)"

# 清理旧的自定义块，避免重复追加
sed -i '/# BEGIN VPS INIT NTP/,/# END VPS INIT NTP/d' "$CHRONY_CONF"

cat >> "$CHRONY_CONF" <<EOF

# BEGIN VPS INIT NTP
server time.cloudflare.com iburst minpoll 4 maxpoll 4
pool pool.ntp.org iburst
# END VPS INIT NTP
EOF

systemctl enable chrony >/dev/null 2>&1
systemctl restart chrony
chronyc makestep || true
echo -e "${GREEN}Chrony 已配置并同步。${NC}"

# =======================================================
# 8. UFW 防火墙
# =======================================================
echo -e "${YELLOW}>> [6/9] 配置 UFW 防火墙 (交互)...${NC}"

read -r -p "是否放行 Web 端口 (80/443)? (y/n, 默认 y): " OPEN_WEB
OPEN_WEB=${OPEN_WEB:-y}

read -r -p "请输入其他需放行端口 (空格分隔, 如: 8080 3000): " OTHER_PORTS

echo -e "正在配置防火墙规则..."
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing

# 先放行旧 SSH 端口和新 SSH 端口
ufw allow 22/tcp comment 'Default SSH Port'
if [ "$UFW_SSH_PORT" != "22" ]; then
    ufw allow "$UFW_SSH_PORT"/tcp comment 'New SSH Port'
fi

if [[ "$OPEN_WEB" =~ ^[Yy]$ ]]; then
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
fi

if [ -n "$OTHER_PORTS" ]; then
    for port in $OTHER_PORTS; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            ufw allow "$port"/tcp
        else
            echo -e "${YELLOW}警告: 跳过非法端口 $port${NC}"
        fi
    done
fi

ufw --force enable
systemctl enable ufw >/dev/null 2>&1
systemctl restart ufw
echo -e "${GREEN}UFW 防火墙已启用。${NC}"

# 重启 SSH 并确认已监听新端口
systemctl restart ssh
sleep 2

if ! ss -lnt | awk '{print $4}' | grep -Eq "(^|:)$UFW_SSH_PORT$"; then
    echo -e "${RED}错误: SSH 未监听在端口 $UFW_SSH_PORT，脚本终止。${NC}"
    exit 1
fi

echo -e "${GREEN}SSH 已确认监听在端口 $UFW_SSH_PORT。${NC}"

# 确认新端口已监听后，删除旧 SSH 端口规则
if [ "$UFW_SSH_PORT" != "22" ]; then
    ufw --force delete allow 22/tcp > /dev/null
    echo -e "${GREEN}旧 SSH 端口 22 的 UFW 规则已删除。${NC}"
fi

# =======================================================
# 9. Fail2Ban
# =======================================================
echo -e "${YELLOW}>> [7/9] 配置 Fail2Ban...${NC}"

echo -e "${CYAN}--- Fail2Ban 参数设置 ---${NC}"

read -r -p "最大重试次数 (回车默认 3 次): " F2B_RETRY
F2B_RETRY=${F2B_RETRY:-3}

echo -e "发现周期(Find Time): 多少分钟内累计错误算作攻击？"
read -r -p "分钟数 (回车默认 10 分钟): " F2B_FIND_MIN
F2B_FIND_MIN=${F2B_FIND_MIN:-10}
F2B_FINDTIME=$((F2B_FIND_MIN * 60))

echo -e "封禁时长: 输入 -1 为永久封禁，否则输入小时数。"
read -r -p "小时数 (回车默认 24 小时): " F2B_HOURS
F2B_HOURS=${F2B_HOURS:-24}

if [ "$F2B_HOURS" = "-1" ]; then
    F2B_BANTIME=-1
    F2B_MSG="永久封禁"
else
    F2B_BANTIME=$((F2B_HOURS * 3600))
    F2B_MSG="封禁 $F2B_HOURS 小时"
fi

mkdir -p /etc/fail2ban/jail.d

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = $UFW_SSH_PORT
filter = sshd
backend = auto
logpath = /var/log/auth.log
banaction = ufw
maxretry = $F2B_RETRY
findtime = $F2B_FINDTIME
bantime = $F2B_BANTIME
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

if ! systemctl is-active --quiet fail2ban; then
    echo -e "${RED}错误: Fail2Ban 服务启动失败，下面输出最近日志：${NC}"
    journalctl -u fail2ban -n 50 --no-pager || true
    exit 1
fi

F2B_OK=0
for i in {1..10}; do
    if fail2ban-client status sshd >/dev/null 2>&1; then
        F2B_OK=1
        break
    fi
    sleep 1
done

if [ "$F2B_OK" -ne 1 ]; then
    echo -e "${RED}错误: Fail2Ban 服务已启动，但 sshd jail 未能在预期时间内完成加载。${NC}"
    fail2ban-client status || true
    journalctl -u fail2ban -n 50 --no-pager || true
    exit 1
fi

echo -e "${GREEN}Fail2Ban 配置完成: ${F2B_FIND_MIN}分钟内错误 ${F2B_RETRY} 次 -> ${F2B_MSG}。${NC}"

# =======================================================
# 10. Swap 虚拟内存设置
# =======================================================
echo -e "${YELLOW}>> [8/9] 配置 Swap 虚拟内存...${NC}"

while true; do
    read -r -p "请输入 Swap 大小(MB) (输入 0 禁用，回车默认 2048): " INPUT_SWAP
    SWAP_SIZE=${INPUT_SWAP:-2048}

    if [[ "$SWAP_SIZE" =~ ^[0-9]+$ ]]; then
        break
    else
        echo -e "${RED}输入错误！请输入 0 或正整数。${NC}"
    fi
done

if [ "$SWAP_SIZE" -gt 0 ]; then
    if swapon --show | grep -q "/swapfile"; then
        echo -e "${GREEN}Swap 已经存在，跳过创建。${NC}"
    else
        echo -e "正在创建 ${SWAP_SIZE}MB Swap 文件 (请耐心等待)..."
        if command -v fallocate >/dev/null 2>&1; then
            fallocate -l "${SWAP_SIZE}M" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_SIZE" status=progress
        else
            dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_SIZE" status=progress
        fi
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        grep -q '^/swapfile none swap sw 0 0$' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap 创建并启用成功。${NC}"
    fi
else
    if swapon --show | grep -q "/swapfile"; then
        swapoff /swapfile || true
        rm -f /swapfile
        sed -i '\|^/swapfile none swap sw 0 0$|d' /etc/fstab
    fi
    echo -e "${GREEN}选择不配置 Swap。${NC}"
fi

# =======================================================
# 11. BBR 拥塞控制
# =======================================================
echo -e "${YELLOW}>> [9/9] 开启 BBR 加速...${NC}"

cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl --system > /dev/null

CURRENT_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
if [ "$CURRENT_CC" = "bbr" ]; then
    echo -e "${GREEN}BBR 已启用。${NC}"
else
    echo -e "${YELLOW}警告: 已写入 BBR 配置，但当前内核未返回 bbr，建议重启后再检查。${NC}"
fi

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}            系统初始化配置完成！               ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. SSH端口:  $UFW_SSH_PORT"
echo -e "2. 认证方式: 仅限密钥 (密码已禁用)"
echo -e "3. NTP同步:  Cloudflare + pool.ntp.org"
echo -e "4. 防火墙:   UFW 已启动"
echo -e "5. 防爆破:   Fail2Ban 已启动"
echo -e "6. BBR:      已配置"
echo -e "7. 时区:     $SYS_TZ"
echo -e "8. Swap内存: ${SWAP_SIZE} MB"

if [ "$UFW_SSH_PORT" != "22" ]; then
    echo -e "${YELLOW}重要提示: 旧 SSH 端口 22 的防火墙规则已自动删除。${NC}"
    echo -e "${YELLOW}请立即新开一个终端窗口，测试新端口 $UFW_SSH_PORT 是否能正常连接。${NC}"
    echo -e "${YELLOW}确认新连接正常前，不要关闭当前窗口。${NC}"
else
    echo -e "${YELLOW}重要提示: 请务必新开一个终端窗口，测试密钥登录是否正常！${NC}"
fi
