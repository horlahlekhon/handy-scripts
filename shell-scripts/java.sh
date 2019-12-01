#!/bin/bash


# install open jdk 8 so that we can have Java8-runtime-headless to run scala
sudo apt  install -y openjdk-8-jdk

#   install oracle jdk8
echo "Starting to install JDK 8"
sudo apt-get purge openjdk-\*
sudo mkdir -p /usr/local/java
tar -xvzf /home/vagrant/demz/packages/jdk-8u231-linux-x64.tar.gz -C  /usr/local/java

JAVA_VERSION=jdk1.8.0_231

sudo tee -a /etc/profile > /dev/null <<EOT
JAVA_HOME=/usr/local/java/$JAVA_VERSION
JRE_HOME=/usr/local/java/$JAVA_VERSION/jre
PATH=$PATH:$JRE_HOME/bin:$JAVA_HOME/bin
export JAVA_HOME
export JRE_HOME
export PATH

EOT

sudo update-alternatives --install "/usr/bin/java" "java" "/usr/local/java/$JAVA_VERSION/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/local/java/$JAVA_VERSION/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/local/java/$JAVA_VERSION/bin/javaws" 1

sudo update-alternatives --set java /usr/local/java/$JAVA_VERSION/bin/java
sudo update-alternatives --set javac /usr/local/java/$JAVA_VERSION/bin/javac
sudo update-alternatives --set javaws /usr/local/java/$JAVA_VERSION/bin/javaws
