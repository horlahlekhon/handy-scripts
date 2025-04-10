#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Update package list and upgrade system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y nginx certbot python3-certbot-nginx curl

# Install Docker and docker compose
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Run docker redis
sudo docker run --name some-redis -P 6379:6379 -d redis redis-server --save 60 1 --loglevel warning


# Verify installations
echo "Verifying installations..."
docker --version
nginx -v
certbot --version
curl --version
docker-compose --version

echo "Installation completed successfully!"
