ansible-galaxy collection install community.docker
ansible-playbook -i hosts.ini setup.yml -e "@vars.yml"