#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   Debian 12 安全配置脚本 (交互自定义版)      ${NC}"
echo -e "${GREEN}==============================================${NC}"

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 权限运行此脚本!${NC}"
  exit 1
fi

# 2. 系统更新
echo -e "${YELLOW}>> [1/5] 更新系统软件包...${NC}"
apt update && apt upgrade -y
apt install -y curl wget git vim ufw fail2ban

# =======================================================
# 3. SSH 密钥配置 (交互部分)
# =======================================================
echo -e "${YELLOW}>> [2/5] 配置 SSH 密钥登录${NC}"
echo -e "${CYAN}请粘贴您的 SSH 公钥 (以 ssh-rsa 或 ssh-ed25519 开头):${NC}"
read -p "公钥内容: " SSH_KEY

if [ -z "$SSH_KEY" ]; then
    echo -e "${RED}错误：未输入公钥，脚本终止以防无法登录。${NC}"
    exit 1
fi

mkdir -p ~/.ssh
chmod 700 ~/.ssh
if ! grep -q "$SSH_KEY" ~/.ssh/authorized_keys; then
    echo "$SSH_KEY" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo -e "${GREEN}公钥已添加。${NC}"
fi

# 修改 SSH 配置文件
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
echo -e "${GREEN}SSH 配置已修改：禁用密码登录，仅允许密钥。${NC}"


# =======================================================
# 4. UFW 防火墙配置 (交互自定义部分)
# =======================================================
echo -e "${YELLOW}>> [3/5] 配置 UFW 防火墙${NC}"

# 自动检测当前 SSH 端口
CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
[ -z "$CURRENT_SSH_PORT" ] && CURRENT_SSH_PORT=22

echo -e "${CYAN}当前检测到的 SSH 端口为: $CURRENT_SSH_PORT${NC}"
read -p "请输入要放行的 SSH 端口 (直接回车使用 $CURRENT_SSH_PORT): " INPUT_SSH_PORT
UFW_SSH_PORT=${INPUT_SSH_PORT:-$CURRENT_SSH_PORT}

read -p "是否放行 Web 端口 (80 和 443)? (y/n, 默认 y): " OPEN_WEB
OPEN_WEB=${OPEN_WEB:-y}

echo -e "${CYAN}请输入其他需要放行的端口 (例如: 8080 3000)${NC}"
read -p "其他端口 (留空则不放行): " OTHER_PORTS

# 开始应用 UFW 规则
ufw reset > /dev/null
ufw default deny incoming
ufw default allow outgoing

# 放行 SSH
ufw allow "$UFW_SSH_PORT"/tcp comment 'SSH Port'
echo -e "${GREEN}已添加规则: 允许端口 $UFW_SSH_PORT (SSH)${NC}"

# 放行 Web
if [[ "$OPEN_WEB" == "y" || "$OPEN_WEB" == "Y" ]]; then
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    echo -e "${GREEN}已添加规则: 允许端口 80, 443 (Web)${NC}"
fi

# 放行自定义端口
if [ -n "$OTHER_PORTS" ]; then
    for port in $OTHER_PORTS; do
        ufw allow "$port"/tcp
        echo -e "${GREEN}已添加规则: 允许自定义端口 $port${NC}"
    done
fi

echo "y" | ufw enable
echo -e "${GREEN}UFW 防火墙已激活！${NC}"


# =======================================================
# 5. Fail2Ban 配置 (交互自定义部分)
# =======================================================
echo -e "${YELLOW}>> [4/5] 配置 Fail2Ban 防暴力破解${NC}"

echo -e "${CYAN}请设置最大尝试次数 (输错几次密码后封禁?)${NC}"
read -p "次数 (回车默认 3 次): " F2B_RETRY
F2B_RETRY=${F2B_RETRY:-3}

echo -e "${CYAN}请设置封禁时长 (封禁多少小时?)${NC}"
read -p "小时数 (回车默认 24 小时): " F2B_HOURS
F2B_HOURS=${F2B_HOURS:-24}

# 将小时转换为秒
F2B_BANTIME=$(($F2B_HOURS * 3600))

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
bantime  = $F2B_BANTIME
findtime = 600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban 配置完成: $F2B_RETRY 次错误封禁 $F2B_HOURS 小时。${NC}"


# =======================================================
# 6. BBR 加速
# =======================================================
echo -e "${YELLOW}>> [5/5] 开启 BBR 加速${NC}"
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null
echo -e "${GREEN}BBR 已开启。${NC}"

# 重启 SSH
systemctl restart sshd

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}          所有配置已完成！                    ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "请新开终端测试 SSH 连接，确认无误后再关闭本窗口。"
