# datamining
apt-get install -y --fix-missing apt-transport-https
sudo apt update

# install java
source./java.sh




# install scala
echo "Starting scala Instalation ; using the package and gdebi"
sudo apt install -y gdebi
sudo gdebi  /home/vagrant/demz/packages/scala-2.13.1.deb


sudo apt --fix-broken install

# install sbt

echo "Starting sbt Instalation ; using the sbt repository"
echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee -a /etc/apt/sources.list.d/sbt.list
curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo apt-key add
sudo apt update
sudo apt install -y sbt
sudo apt --fix-broken install


# Install redis
echo "Starting Redis Instalation ; using apt"
 sudo apt --fix-broken install -y
sudo apt install -y redis*
sudo apt install -y redis-tools
sudo apt-get install -y  redis-server
sudo systemctl enable redis-server.service


# install google protobuf

echo "Begining configiration and installation of protobuf "
wget https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz
tar xzf protobuf-2.6.1.tar.gz
cd protobuf-2.6.1
sudo apt-get update
sudo apt-get install build-essential
sudo ./configure
sudo make
sudo make check
sudo make install
sudo ldconfig
protoc --version


# configure google cloud

echo 'export GOOGLE_APPLICATION_CREDENTIALS=/home/vagrant/demz/cosmic-axe-163012-607d58aadab8.json' >> ~/.bashrc && source ~/.bashrc