#!/bin/bash

# ==============================================================================
# 脚本名称: Debian 12 VPS 初始化全能脚本
# 功能: SSH加固 / UFW(交互) / Fail2Ban(读取auth.log) / BBR / NTP(Cloudflare)
# ==============================================================================

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 指定的 SSH 公钥
MY_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvyH3RGNA/b9OuBLnHIpzmFIOQuWSpSt2bdgyPjoujE admin@gmail.com"

echo -e "${GREEN}=== 开始执行 VPS 初始化配置 (Rsyslog Integrated) ===${NC}"

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}错误: 请使用 root 权限运行此脚本!${NC}"
  exit 1
fi

# 2. 更新系统与安装依赖
echo -e "${YELLOW}>> [1/6] 更新系统与安装依赖...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y
apt install -y curl wget git vim ufw fail2ban chrony rsyslog

# 关键步骤：立即启动 rsyslog 以生成日志文件，防止 Fail2Ban 报错
echo -e "${YELLOW}正在启动 Rsyslog 服务...${NC}"
systemctl enable --now rsyslog
# 等待一秒确保文件创建
sleep 1
if [ -f /var/log/auth.log ]; then
    echo -e "${GREEN}系统日志文件 auth.log 已就绪。${NC}"
else
    # 如果文件还不存在，手动创建它以防万一
    touch /var/log/auth.log
    echo -e "${GREEN}手动创建 auth.log 以确保兼容性。${NC}"
fi

# =======================================================
# 3. SSH 配置
# =======================================================
echo -e "${YELLOW}>> [2/6] 配置 SSH 安全选项...${NC}"

# 3.1 写入公钥
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# 使用 grep 精确匹配防止重复追加
if ! grep -q "$MY_SSH_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "$MY_SSH_KEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo -e "${GREEN}指定公钥已添加。${NC}"
else
    echo -e "${GREEN}指定公钥已存在，跳过添加。${NC}"
fi

# 3.2 修改 SSHD 配置文件
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%T)

update_sshd_config() {
    local param=$1
    local value=$2
    local file="/etc/ssh/sshd_config"
    
    if grep -q "^#\?$param" "$file"; then
        sed -i "s/^#\?$param.*/$param $value/" "$file"
    else
        echo "$param $value" >> "$file"
    fi
}

echo -e "正在应用安全策略..."
update_sshd_config "PasswordAuthentication" "no"          # 禁止密码
update_sshd_config "PermitEmptyPasswords" "no"            # 禁止空密码
update_sshd_config "ChallengeResponseAuthentication" "no" # 禁用挑战响应
update_sshd_config "KbdInteractiveAuthentication" "no"    # 禁用键盘交互
update_sshd_config "PubkeyAuthentication" "yes"           # 启用公钥
update_sshd_config "UseDNS" "no"                          # 禁用 DNS 反查
update_sshd_config "X11Forwarding" "no"                   # 禁用 X11
update_sshd_config "PermitRootLogin" "prohibit-password"  # 允许Root密钥登录

echo -e "${GREEN}SSH 安全配置已更新。${NC}"

# =======================================================
# 4. NTP 时间同步 (Chrony + Cloudflare)
# =======================================================
echo -e "${YELLOW}>> [3/6] 配置 NTP 时间同步 (Cloudflare)...${NC}"
cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.bak 2>/dev/null

# 清理默认池并添加 Cloudflare
sed -i '/^pool/d' /etc/chrony/chrony.conf
sed -i '/^server/d' /etc/chrony/chrony.conf
sed -i '1i server time.cloudflare.com iburst minpoll 4 maxpoll 4' /etc/chrony/chrony.conf

systemctl restart chrony
systemctl enable chrony
chronyc makestep
echo -e "${GREEN}Chrony 已配置并同步。${NC}"

# =======================================================
# 5. UFW 防火墙
# =======================================================
echo -e "${YELLOW}>> [4/6] 配置 UFW 防火墙 (交互)...${NC}"

CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
[ -z "$CURRENT_SSH_PORT" ] && CURRENT_SSH_PORT=22

echo -e "${CYAN}检测到 SSH 当前监听端口: $CURRENT_SSH_PORT${NC}"
read -p "请输入防火墙要放行的 SSH 端口 (回车默认 $CURRENT_SSH_PORT): " INPUT_SSH_PORT
UFW_SSH_PORT=${INPUT_SSH_PORT:-$CURRENT_SSH_PORT}

# 安全警告
if [ "$UFW_SSH_PORT" != "$CURRENT_SSH_PORT" ]; then
    echo -e "${RED}警告: 您放行的端口 ($UFW_SSH_PORT) 与 SSH 当前配置 ($CURRENT_SSH_PORT) 不一致！${NC}"
    echo -e "${RED}除非您稍后会手动修改 sshd_config，否则可能会无法连接。${NC}"
    read -p "按回车继续，或按 Ctrl+C 终止脚本..."
fi

read -p "是否放行 Web 端口 (80/443)? (y/n, 默认 y): " OPEN_WEB
OPEN_WEB=${OPEN_WEB:-y}

read -p "请输入其他需放行端口 (空格分隔, 如: 8080 3000): " OTHER_PORTS

# --- 执行配置 ---
echo -e "正在配置防火墙规则..."
# 强制重置，不询问
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing

ufw allow "$UFW_SSH_PORT"/tcp comment 'SSH Port'

if [[ "$OPEN_WEB" =~ ^[Yy] ]]; then
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
fi

if [ -n "$OTHER_PORTS" ]; then
    for port in $OTHER_PORTS; do
        ufw allow "$port"/tcp
    done
fi

# 启用防火墙 (自动确认)
echo "y" | ufw enable
systemctl enable ufw
echo -e "${GREEN}UFW 防火墙已启用。${NC}"

# =======================================================
# 6. Fail2Ban
# =======================================================
echo -e "${YELLOW}>> [5/6] 配置 Fail2Ban...${NC}"

echo -e "${CYAN}--- Fail2Ban 参数设置 ---${NC}"

read -p "最大重试次数 (回车默认 3 次): " F2B_RETRY
F2B_RETRY=${F2B_RETRY:-3}

echo -e "发现周期(Find Time): 多少分钟内累计错误算作攻击？"
read -p "分钟数 (回车默认 10 分钟): " F2B_FIND_MIN
F2B_FIND_MIN=${F2B_FIND_MIN:-10}
F2B_FINDTIME=$(($F2B_FIND_MIN * 60))

echo -e "封禁时长: 输入 -1 为永久封禁，否则输入小时数。"
read -p "小时数 (回车默认 24 小时): " F2B_HOURS
F2B_HOURS=${F2B_HOURS:-24}

if [ "$F2B_HOURS" == "-1" ]; then
    F2B_BANTIME=-1
    F2B_MSG="永久封禁"
else
    F2B_BANTIME=$(($F2B_HOURS * 3600))
    F2B_MSG="封禁 $F2B_HOURS 小时"
fi

# 写入配置 (jail.local)
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local 2>/dev/null

# 写入 SSH 专用规则 (jail.d)
cat <<EOF > /etc/fail2ban/jail.d/sshd_custom.conf
[sshd]
enabled = true
port    = $UFW_SSH_PORT
filter  = sshd
logpath = /var/log/auth.log
backend = systemd
maxretry = $F2B_RETRY
findtime = $F2B_FINDTIME
bantime  = $F2B_BANTIME
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban 配置完成: 监听 auth.log, ${F2B_FIND_MIN}分钟内错误 ${F2B_RETRY} 次 -> ${F2B_MSG}。${NC}"

# =======================================================
# 7. BBR拥塞控制
# =======================================================
echo -e "${YELLOW}>> [6/6] 开启 BBR 加速...${NC}"

if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null
echo -e "${GREEN}BBR 已启用。${NC}"

# 重启 SSH 服务以应用更改
systemctl restart sshd

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}             系统初始化配置完成！               ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. SSH端口:  $UFW_SSH_PORT"
echo -e "2. 安全认证:  密钥 (密码已禁用)"
echo -e "3. NTP同步:  Cloudflare 已校准"
echo -e "4. 防火墙:   UFW 已启动"
echo -e "5. 防爆破:   Fail2Ban 已启动"
echo -e "6. BBR:      已开启"
echo -e "${YELLOW}重要提示: 请务必新开一个终端窗口，测试是否能通过密钥成功连接！${NC}"
echo -e "${YELLOW}确认连接无误后，再关闭当前窗口。${NC}"
