#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Update package list and upgrade system
sudo apt update && sudo apt upgrade -y

# usage: ./server_config.sh <username> <password> "<ssh_pub_key>""

#!/bin/bash

# Exit on error
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# --- Variables ---
USERNAME="$1"
PASSWORD="$2"
SSH_KEY="$3"   # Optional public key

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "Usage: $0 <username> <password> <ssh_pub_key>"
    exit 1
fi

# --- Check if user already exists ---
if id "$USERNAME" &>/dev/null; then
    echo "User '$USERNAME' already exists. Skipping user creation."
else
    echo "Creating user: $USERNAME"
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
fi

# --- Ensure user is in sudo group ---
echo "Adding $USERNAME to sudo group"
usermod -aG sudo "$USERNAME"

# --- Configure SSH directory ---
SSH_DIR="/home/$USERNAME/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [ -n "$SSH_KEY" ]; then
    echo "Setting SSH public key for $USERNAME"
    echo "$SSH_KEY" > "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
fi

chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

# --- Enable Password Authentication in SSH ---
echo "Enabling password authentication in SSH"

sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Ensure PubkeyAuthentication is enabled
sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

systemctl restart ssh

echo "----------------------------------------"
echo "User $USERNAME setup complete."
echo "* Password set (if newly created)"
echo "* SSH key installed (if provided)"
echo "* Added to sudo group"
echo "* SSH password login enabled"
echo "----------------------------------------"



echo "=== Removing old Docker versions ==="
apt-get remove -y docker.io docker-doc docker-compose docker-compose-v2 \
    podman-docker containerd runc || true

echo "=== Installing prerequisites ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release

echo "=== Adding Docker’s official GPG key ==="
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "=== Adding Docker APT repository ==="
echo "=== Adding Docker APT repository ==="
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y



apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Install required packages
sudo apt install -y nginx certbot python3-certbot-nginx curl

# Enable and start Nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Run docker redis
# sudo docker run --name some-redis -P 6379:6379 -d redis redis-server --save 60 1 --loglevel warning
# 

# Verify installations
echo "Verifying installations..."
docker --version
nginx -v
certbot --version
curl --version
docker compose --version

echo "Installation completed successfully!"


sudo chmod 600 /home/$USERNAME/.ssh/authorized_keys
sudo chown "$USERNAME":"$USERNAME" /home/$USERNAME/.ssh/authorized_keys

sudo usermod -aG docker "$USERNAME"

