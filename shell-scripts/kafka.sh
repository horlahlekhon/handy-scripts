#!/bin/bash

#require java first TODO :we should try tocheck if java is installed so we can be atleast intuitive
source java.sh
# Install kafka
wget http://www-us.apache.org/dist/kafka/2.2.1/kafka_2.12-2.2.1.tgz

sudo tar -xvzf kafka_2.12-2.2.1.tgz -C /usr/local/

cd /usr/local/kafka_2.12-2.2.1

bin/zookeeper-server-start.sh config/zookeeper.properties  &

bin/kafka-server-start.sh config/server.properties   &

