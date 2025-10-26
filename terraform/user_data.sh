#!/bin/bash
set -e
echo "Installing docker..."

apt-get -q update
apt-get -q install -y apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
apt-get -q update
apt-cache policy docker-ce
apt-get -q install -y docker-ce

systemctl enable docker
systemctl start docker
systemctl status docker || true

# Allow default user (ubuntu) to run docker without sudo
usermod -aG docker ubuntu
newgrp docker <<EONG
docker version
EONG

echo "Installing docker-compose..."
curl -sL https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version
