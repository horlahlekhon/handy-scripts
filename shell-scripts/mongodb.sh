#!/bin/bash


#Install mongodb

wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
sudo apt-get install gnupg
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-org-shell hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections
sudo service mongod start
sudo service mongod status


### run setup for mongo
mongo core <<\EOF
    db.createUser({
      user: "admin",
      pwd: "chelsea",
      roles: [
                { role: "userAdminAnyDatabase", db: "admin" },
                { role: "readWriteAnyDatabase", db: "admin" },
                { role: "dbAdminAnyDatabase",   db: "admin" }
             ]
  });

  db.createUser({
      user: "deepview",
      pwd: "chelsea",
      roles: [
                { role: "userAdmin", db: "core" },
                { role: "dbAdmin",   db: "core" },
                { role: "readWrite", db: "core" }
             ]
  });
EOF

# Install mongodb gui
