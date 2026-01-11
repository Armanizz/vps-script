#!/bin/bash

# 定义颜色输出，方便查看进度
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== 开始配置 Debian 12 服务器 (安全 + 防火墙 + 防爆破 + BBR) ===${NC}"

# 1. 检查是否为 Root 用户
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}错误：请使用 root 权限运行此脚本 (sudo bash script.sh)${NC}"
  exit
fi

# 2. 更新系统
echo -e "${YELLOW}>> [1/6] 正在更新系统软件包...${NC}"
apt update && apt upgrade -y
apt install -y curl wget git vim

# 3. 配置 SSH 密钥登录
echo -e "${YELLOW}>> [2/6] 配置 SSH 密钥登录...${NC}"
read -p "请输入您的 SSH 公钥 (ssh-rsa ... / ssh-ed25519 ...): " SSH_KEY

if [ -z "$SSH_KEY" ]; then
    echo -e "${RED}未提供 SSH 公钥，脚本退出以防被锁定。${NC}"
    exit 1
fi

mkdir -p ~/.ssh
chmod 700 ~/.ssh
# 检查是否已存在，避免重复添加
if ! grep -q "$SSH_KEY" ~/.ssh/authorized_keys; then
    echo "$SSH_KEY" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo -e "${GREEN}SSH 公钥已添加。${NC}"
else
    echo -e "${YELLOW}SSH 公钥已存在，跳过。${NC}"
fi

# 备份 SSH 配置文件
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 修改 SSH 配置: 禁用密码验证，启用密钥验证
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

echo -e "${GREEN}SSH 配置已优化 (已禁用密码登录)。${NC}"

# 4. 安装并自定义配置 UFW 防火墙
echo -e "${YELLOW}>> [3/6] 安装并配置 UFW 防火墙...${NC}"
apt install -y ufw

# === UFW 自定义配置开始 ===
# 自动检测当前的 SSH 端口（非常重要，防止自己被锁在外面）
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22 # 如果没找到配置，默认认为是22
fi
echo -e "检测到 SSH 端口为: ${GREEN}$SSH_PORT${NC}"

# 重置 UFW 规则
echo "y" | ufw reset > /dev/null

# 设置默认策略
ufw default deny incoming  # 拒绝所有进入
ufw default allow outgoing # 允许所有流出

# 开放关键端口
ufw allow "$SSH_PORT"/tcp comment 'SSH Port' # 放行 SSH
ufw allow 80/tcp comment 'HTTP'              # 放行 Web HTTP
ufw allow 443/tcp comment 'HTTPS'            # 放行 Web HTTPS

# 启用防火墙 (自动输入 y 确认)
echo "y" | ufw enable
echo -e "${GREEN}UFW 防火墙已启用并加载自定义规则。${NC}"
# === UFW 自定义配置结束 ===


# 5. 安装并自定义配置 Fail2Ban
echo -e "${YELLOW}>> [4/6] 安装并配置 Fail2Ban...${NC}"
apt install -y fail2ban

# === Fail2Ban 自定义配置开始 ===
# 复制默认配置文件（标准做法）
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# 创建针对 SSH 的强化规则文件
# 位于 jail.d 下的文件优先级更高，管理更清晰
cat <<EOF > /etc/fail2ban/jail.d/sshd_custom.conf
[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
logpath = /var/log/auth.log
backend = systemd

# --- 自定义封禁规则 ---
# 10分钟(600秒)内
findtime = 600
# 尝试失败 3 次
maxretry = 3
# 封禁 1 天 (86400秒)
bantime  = 86400
# 忽略的 IP (可以在这里填你自己的固定IP，如果需要)
# ignoreip = 127.0.0.1/8
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban 已安装。策略：10分钟内输错3次，封禁1天。${NC}"
# === Fail2Ban 自定义配置结束 ===


# 6. 开启 BBR 加速
echo -e "${YELLOW}>> [5/6] 开启 BBR 加速...${NC}"
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null
echo -e "${GREEN}BBR 已开启。${NC}"


# 7. 收尾工作
echo -e "${YELLOW}>> [6/6] 正在重启 SSH 服务...${NC}"
systemctl restart sshd

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}      VPS 安全配置脚本执行完成！             ${NC}"
echo -e "${GREEN}=============================================${NC}"
echo -e "1. SSH 端口: $SSH_PORT"
echo -e "2. 密码登录: 已禁用 (仅限密钥)"
echo -e "3. 防火墙: 已开启 (开放端口: $SSH_PORT, 80, 443)"
echo -e "4. Fail2Ban: 已开启 (3次错误封禁1天)"
echo -e "5. BBR加速: 已开启"
echo -e "${YELLOW}请务必新开一个终端窗口进行连接测试，确保一切正常后再关闭当前窗口！${NC}"
