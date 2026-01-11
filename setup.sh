#!/bin/bash

# ==============================================================================
# 脚本名称: Debian 12 VPS 初始化全能脚本
# 功能: SSH加固(指定公钥), UFW防火墙(交互), Fail2Ban(交互), BBR, NTP(Cloudflare)
# ==============================================================================

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 指定的 SSH 公钥
MY_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvyH3RGNA/b9OuBLnHIpzmFIOQuWSpSt2bdgyPjoujE admin@gmail.com"

echo -e "${GREEN}=== 开始执行 VPS 初始化配置 ===${NC}"

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}错误: 请使用 root 权限运行此脚本!${NC}"
  exit 1
fi

# 2. 更新系统并安装必要软件
echo -e "${YELLOW}>> [1/6] 更新系统与安装依赖...${NC}"
apt update && apt upgrade -y
apt install -y curl wget git vim ufw fail2ban chrony

# =======================================================
# 3. SSH 配置 (硬编码公钥 + 深度加固)
# =======================================================
echo -e "${YELLOW}>> [2/6] 配置 SSH 安全选项...${NC}"

# 3.1 写入公钥
mkdir -p ~/.ssh
chmod 700 ~/.ssh
# 覆盖写入 (保证绝对由该Key控制) 或者 追加写入
# 这里使用判断追加，防止重复
if ! grep -q "$MY_SSH_KEY" ~/.ssh/authorized_keys; then
    echo "$MY_SSH_KEY" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo -e "${GREEN}指定公钥已添加。${NC}"
else
    echo -e "${GREEN}指定公钥已存在，跳过添加。${NC}"
fi

# 3.2 修改 SSHD 配置文件
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 辅助函数：修改或添加配置
update_sshd_config() {
    local param=$1
    local value=$2
    if grep -q "^#\?$param" /etc/ssh/sshd_config; then
        sed -i "s/^#\?$param.*/$param $value/" /etc/ssh/sshd_config
    else
        echo "$param $value" >> /etc/ssh/sshd_config
    fi
}

# 执行各项安全配置
echo -e "正在应用安全策略..."
update_sshd_config "PasswordAuthentication" "no"          # 禁止密码登录
update_sshd_config "PermitEmptyPasswords" "no"            # 禁止空密码
update_sshd_config "ChallengeResponseAuthentication" "no" # 禁用挑战响应
update_sshd_config "KbdInteractiveAuthentication" "no"    # 禁用键盘交互
update_sshd_config "PubkeyAuthentication" "yes"           # 启用公钥认证
update_sshd_config "UseDNS" "no"                          # 禁用 DNS 反查 (加快登录)
update_sshd_config "X11Forwarding" "no"                   # 禁用 X11 转发
update_sshd_config "PermitRootLogin" "prohibit-password"  # 允许Root密钥登录

echo -e "${GREEN}SSH 安全加固完成。${NC}"

# =======================================================
# 4. NTP 时间同步 (Chrony + Cloudflare)
# =======================================================
echo -e "${YELLOW}>> [3/6] 配置 NTP 时间同步 (Cloudflare)...${NC}"

# 备份原始配置
cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.bak

# 配置 Cloudflare NTP 源
# 清除默认 pool/server 设置并添加 cloudflare
sed -i '/^pool/d' /etc/chrony/chrony.conf
sed -i '/^server/d' /etc/chrony/chrony.conf
sed -i '1i server time.cloudflare.com iburst minpoll 4 maxpoll 4' /etc/chrony/chrony.conf

# 重启 Chrony 并强制同步
systemctl restart chrony
systemctl enable chrony
# 强制同步一次
chronyc makestep
echo -e "${GREEN}Chrony 已配置为使用 time.cloudflare.com。${NC}"

# =======================================================
# 5. UFW 防火墙 (交互式)
# =======================================================
echo -e "${YELLOW}>> [4/6] 配置 UFW 防火墙 (交互)...${NC}"

# 检测 SSH 端口
CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
[ -z "$CURRENT_SSH_PORT" ] && CURRENT_SSH_PORT=22

echo -e "${CYAN}当前 SSH 端口: $CURRENT_SSH_PORT${NC}"
read -p "确认要放行的 SSH 端口 (回车默认 $CURRENT_SSH_PORT): " INPUT_SSH_PORT
UFW_SSH_PORT=${INPUT_SSH_PORT:-$CURRENT_SSH_PORT}

read -p "是否放行 Web 端口 (80/443)? (y/n, 默认 y): " OPEN_WEB
OPEN_WEB=${OPEN_WEB:-y}

read -p "请输入其他需放行端口 (空格分隔, 如: 8080 3000): " OTHER_PORTS

# 重置并应用规则
ufw reset > /dev/null
ufw default deny incoming
ufw default allow outgoing

ufw allow "$UFW_SSH_PORT"/tcp comment 'SSH Port'

if [[ "$OPEN_WEB" =~ ^[Yy]$ ]]; then
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
echo -e "${GREEN}UFW 防火墙配置完毕。${NC}"

# =======================================================
# 6. Fail2Ban (深度交互)
# =======================================================
echo -e "${YELLOW}>> [5/6] 配置 Fail2Ban (交互)...${NC}"

echo -e "${CYAN}--- 配置参数 ---${NC}"

# 1. 重试次数
read -p "最大重试次数 (回车默认 3 次): " F2B_RETRY
F2B_RETRY=${F2B_RETRY:-3}

# 2. 发现周期
echo -e "发现周期(Find Time): 在多长时间内累计达到重试次数则封禁？"
read -p "分钟数 (回车默认 10 分钟): " F2B_FIND_MIN
F2B_FIND_MIN=${F2B_FIND_MIN:-10}
F2B_FINDTIME=$(($F2B_FIND_MIN * 60))

# 3. 封禁时长
echo -e "封禁时长(Ban Time): 输入 -1 为永久封禁，否则输入小时数。"
read -p "小时数 (回车默认 24 小时): " F2B_HOURS
F2B_HOURS=${F2B_HOURS:-24}

if [ "$F2B_HOURS" == "-1" ]; then
    F2B_BANTIME=-1
    F2B_MSG="永久封禁"
else
    F2B_BANTIME=$(($F2B_HOURS * 3600))
    F2B_MSG="封禁 $F2B_HOURS 小时"
fi

# 写入配置
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
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
echo -e "${GREEN}Fail2Ban 规则: ${F2B_FIND_MIN}分钟内错误 ${F2B_RETRY} 次 -> ${F2B_MSG}。${NC}"

# =======================================================
# 7. BBR 加速 & 收尾
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

# 重启 SSH 服务
systemctl restart sshd

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   系统初始化完成！请检查以下信息             ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. SSH 端口: $UFW_SSH_PORT"
echo -e "2. 认证方式: 仅限公钥 (密码/交互已禁用)"
echo -e "3. 时间同步: Cloudflare NTP (已同步)"
echo -e "4. 防火墙:   已启动"
echo -e "5. Fail2Ban: 已启动 ($F2B_MSG)"
echo -e "${YELLOW}警告: 请务必新开终端测试 SSH 连接，成功后再关闭当前窗口！${NC}"
