
Vagrant.configure("2") do |config|

  config.vm.define "datamining" do |datamining|
    datamining.vm.box = "debian/buster64"
    datamining.vm.network "private_network", ip: "192.168.10.21"
    datamining.vm.hostname = "datamining"
    datamining.vm.synced_folder "/home/lekan/Documents/workspace/demz/", "/home/vagrant/demz/"

    datamining.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "2096"]
      vb.customize ["modifyvm", :id, "--cpus", "2"]
    end

    datamining.vm.provision :shell do |shell|
      shell.path = './vagrant/run.sh'
    end
  end

  config.vm.define "dataprocessing" do |dataprocessing|
    dataprocessing.vm.box = "debian/buster64"
    dataprocessing.vm.network "private_network", ip: "192.168.10.22"
    dataprocessing.vm.hostname = "dataprocessing"
    dataprocessing.vm.synced_folder "/home/lekan/Documents/workspace/demz/", "/home/vagrant/demz/"

    dataprocessing.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1096"]
      vb.customize ["modifyvm", :id, "--cpus", "1"]
    end

    dataprocessing.vm.provision :shell do |shell|
      shell.path = './vagrant/run.sh'
    end
  end

  config.vm.define "mongodb" do |mongodb|
    mongodb.vm.box = "debian/buster64"
    mongodb.vm.network "private_network", ip: "192.168.10.23"
    mongodb.vm.hostname = "mongodb"
    mongodb.vm.synced_folder "/home/lekan/Documents/workspace/demz/", "/home/vagrant/demz"
    mongodb.vm.network "forwarded_port", guest: 27017, host: 27017
    mongodb.vm.network "forwarded_port", guest: 9092, host: 9092


    mongodb.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1096"]
      vb.customize ["modifyvm", :id, "--cpus", "1"]
    end

    mongodb.vm.provision :shell do |shell|
      shell.path = './vagrant/run.sh'
      shell.path = './vagrant/kafka.sh'
      shell.path = './vagrant/mongodb.sh'
    end
  end

  config.vm.define "whatsapp" do |whatsapp|
    whatsapp.vm.box = "debian/buster64"
    whatsapp.vm.network "private_network", ip: "192.168.10.24"
    whatsapp.vm.hostname = "whatsapp"
    whatsapp.vm.synced_folder "/home/lekan/Documents/workspace/demz/", "/home/vagrant/demz/"
    whatsapp.vm.network "forwarded_port", guest: 8008, host: 8008


    whatsapp.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1096"]
      vb.customize ["modifyvm", :id, "--cpus", "1"]
    end

    whatsapp.vm.provision :shell do |shell|
      shell.path = './vagrant/run.sh'
    end
  end

  config.vm.define "frontend" do |frontend|
    frontend.vm.box = "debian/buster64"
    frontend.vm.network "private_network", ip: "192.168.10.25"
    frontend.vm.hostname = "frontend"
    frontend.vm.synced_folder "/home/lekan/Documents/workspace/demz/", "/home/vagrant/demz/"
    frontend.vm.network "forwarded_port", guest: 1337, host: 1337

    frontend.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1096"]
      vb.customize ["modifyvm", :id, "--cpus", "1"]
    end

    # frontend.vm.provision :shell do |shell|
    #   shell.path = './vagrant/run.sh'
    # end
  end


end
