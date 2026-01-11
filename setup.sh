#!/bin/bash

# 定义颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== 开始配置 Debian 12 服务器安全性 ===${NC}"

# 1. 检查是否为 Root 用户
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 权限运行此脚本 (sudo bash script.sh)${NC}"
  exit
fi

# 2. 更新系统
echo -e "${YELLOW}正在更新系统软件包...${NC}"
apt update && apt upgrade -y
apt install -y curl wget git vim

# 3. 配置 SSH 密钥登录
echo -e "${YELLOW}=== 配置 SSH 密钥登录 ===${NC}"
read -p "请输入您的 SSH 公钥 (ssh-rsa ... / ssh-ed25519 ...): " SSH_KEY

if [ -z "$SSH_KEY" ]; then
    echo -e "${RED}未提供 SSH 公钥，脚本退出以防被锁定。${NC}"
    exit 1
fi

# 创建 .ssh 目录并设置权限
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "$SSH_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo -e "${GREEN}SSH 公钥已添加。${NC}"

# 备份 SSH 配置文件
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 修改 SSH 配置 (禁用密码登录)
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# 确保包含配置目录 (Debian 12 默认做法)
# 也可以直接修改 sshd_config，上面的 sed 命令已经足够覆盖大多数情况

echo -e "${GREEN}SSH 配置已修改 (已禁用密码登录)。${NC}"

# 4. 配置 UFW 防火墙
echo -e "${YELLOW}=== 配置 UFW 防火墙 ===${NC}"
apt install -y ufw

# 获取当前 SSH 端口 (防止用户修改了默认端口后被锁)
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi

echo -e "检测到 SSH 端口为: ${GREEN}$SSH_PORT${NC}"

ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# 自动确认开启
echo "y" | ufw enable
echo -e "${GREEN}UFW 已开启并配置。${NC}"

# 5. 配置 Fail2Ban
echo -e "${YELLOW}=== 配置 Fail2Ban ===${NC}"
apt install -y fail2ban

# 创建本地配置文件 (不要直接修改 jail.conf)
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# 简单的配置：针对 sshd 启用保护
cat <<EOF > /etc/fail2ban/jail.d/sshd_custom.conf
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban 已安装并启动。${NC}"

# 6. 重启 SSH 服务
echo -e "${YELLOW}正在重启 SSH 服务以应用更改...${NC}"
systemctl restart sshd

echo -e "${GREEN}=== 配置完成！ ===${NC}"
echo -e "${YELLOW}请不要关闭当前终端！${NC}"
echo -e "请新开一个终端窗口，尝试使用 SSH 密钥连接服务器。"
echo -e "如果没有问题，您的服务器现在更加安全了。"
