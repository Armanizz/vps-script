#!/bin/bash

# ==============================================================================
# 脚本名称: Debian 12 VPS 初始化全能脚本 (完美最终版)
# 功能: SSH加固 / UFW / Fail2Ban(联动UFW+读auth.log) / BBR / NTP / 日志权限
# ==============================================================================

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 指定的 SSH 公钥
MY_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvyH3RGNA/b9OuBLnHIpzmFIOQuWSpSt2bdgyPjoujE admin@gmail.com"

echo -e "${GREEN}=== 开始执行 VPS 初始化配置 (Fail2Ban + UFW Link) ===${NC}"

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

# =======================================================
# 3. 日志环境初始化
# =======================================================
echo -e "${YELLOW}>> [2/6] 初始化系统日志环境...${NC}"

# 1. 确保 Rsyslog 开机自启并立即运行
systemctl enable --now rsyslog

# 2. 等待服务初始化
sleep 2

# 3. 确保日志文件存在
LOG_FILE="/var/log/auth.log"
if [ ! -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    echo -e "${GREEN}已手动创建 auth.log 文件。${NC}"
fi

# 4. 设置标准安全权限 (640 + root:adm)
chmod 640 "$LOG_FILE"
chown root:adm "$LOG_FILE"
echo -e "${GREEN}日志权限已修正为 640 (root:adm)。${NC}"

# =======================================================
# 4. SSH 配置
# =======================================================
echo -e "${YELLOW}>> [3/6] 配置 SSH 安全选项...${NC}"

# 4.1 写入公钥
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if ! grep -q "$MY_SSH_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "$MY_SSH_KEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo -e "${GREEN}指定公钥已添加。${NC}"
else
    echo -e "${GREEN}指定公钥已存在，跳过添加。${NC}"
fi

# 4.2 修改 SSHD 配置文件
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
# 5. NTP 时间同步 (Chrony + Cloudflare)
# =======================================================
echo -e "${YELLOW}>> [4/6] 配置 NTP 时间同步 (Cloudflare)...${NC}"
cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.bak 2>/dev/null

sed -i '/^pool/d' /etc/chrony/chrony.conf
sed -i '/^server/d' /etc/chrony/chrony.conf
sed -i '1i server time.cloudflare.com iburst minpoll 4 maxpoll 4' /etc/chrony/chrony.conf

systemctl restart chrony
systemctl enable chrony
chronyc makestep
echo -e "${GREEN}Chrony 已配置并同步。${NC}"

# =======================================================
# 6. UFW 防火墙
# =======================================================
echo -e "${YELLOW}>> [5/6] 配置 UFW 防火墙 (交互)...${NC}"

CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
[ -z "$CURRENT_SSH_PORT" ] && CURRENT_SSH_PORT=22

echo -e "${CYAN}检测到 SSH 当前监听端口: $CURRENT_SSH_PORT${NC}"
read -p "请输入防火墙要放行的 SSH 端口 (回车默认 $CURRENT_SSH_PORT): " INPUT_SSH_PORT
UFW_SSH_PORT=${INPUT_SSH_PORT:-$CURRENT_SSH_PORT}

if [ "$UFW_SSH_PORT" != "$CURRENT_SSH_PORT" ]; then
    echo -e "${RED}警告: 您放行的端口 ($UFW_SSH_PORT) 与 SSH 当前配置 ($CURRENT_SSH_PORT) 不一致！${NC}"
    echo -e "${RED}除非您稍后会手动修改 sshd_config，否则可能会无法连接。${NC}"
    read -p "按回车继续，或按 Ctrl+C 终止脚本..."
fi

read -p "是否放行 Web 端口 (80/443)? (y/n, 默认 y): " OPEN_WEB
OPEN_WEB=${OPEN_WEB:-y}

read -p "请输入其他需放行端口 (空格分隔, 如: 8080 3000): " OTHER_PORTS

echo -e "正在配置防火墙规则..."
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

echo "y" | ufw enable
systemctl enable ufw
echo -e "${GREEN}UFW 防火墙已启用。${NC}"

# =======================================================
# 7. Fail2Ban
# =======================================================
echo -e "${YELLOW}>> [6/6] 配置 Fail2Ban...${NC}"

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

cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local 2>/dev/null

# 写入配置 (关键修改：加入 banaction = ufw)
cat <<EOF > /etc/fail2ban/jail.d/sshd_custom.conf
[sshd]
enabled = true
port    = $UFW_SSH_PORT
filter  = sshd
logpath = /var/log/auth.log
banaction = ufw
maxretry = $F2B_RETRY
findtime = $F2B_FINDTIME
bantime  = $F2B_BANTIME
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban 配置完成: 联动UFW, 监听auth.log。${NC}"

# =======================================================
# 8. BBR 加速 & 收尾
# =======================================================
echo -e "${YELLOW}>> [Final] 开启 BBR 加速与重启服务...${NC}"

if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null
echo -e "${GREEN}BBR 已启用。${NC}"

systemctl restart sshd

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}           系统初始化配置完成！               ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. SSH端口:  $UFW_SSH_PORT"
echo -e "2. 认证方式: 仅限密钥 (密码已禁用)"
echo -e "3. 日志安全: auth.log (权限 640)"
echo -e "4. 防火墙:   UFW 已启动"
echo -e "5. 防爆破:   Fail2Ban (联动 UFW)"
echo -e "6. BBR:      已开启"
echo -e "${YELLOW}请务必新开一个终端窗口，测试是否能通过密钥成功连接！${NC}"
