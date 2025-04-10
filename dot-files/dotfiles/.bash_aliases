#!/bin/bash -
#===============================================================================
#
#          FILE: .bash_aliases.sh
#
#         USAGE: ./.bash_aliases.sh
#
#   DESCRIPTION: my custom alias files
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Adebari Olalekan Oluwaseun,
#  ORGANIZATION:
#       CREATED: 26/05/2019 07:37
#      REVISION:  ---
#===============================================================================

# -L "FILE" : FILE exists and is a symbolic link (same as -h)
# -h "FILE" : FILE exists and is a symbolic link (same as -L)
#-d "FILE" : FILE exists and is a directory
# -w "FILE" : FILE exists and write permission is granted

alias ll='ls -l'
alias la='ls -Alha'
alias l='ls -CF'


alias goedit='goedit > /dev/null 2>&1 &'
alias idea='idea > /dev/null 2>&1 &'
# alias postman='postman > /dev/null 2>&1 &'
# alias cp='rsync --progress -rhaHAXv'  # rsync having issues with mac version
# Rsync options
# -a is for archive, which preserves ownership, permissions etc.
# -v is for verbose, so I can see what's happening (optional)
# -h is for human-readable, so the transfer rate and file sizes are easier to read (optional)
# -W is for copying whole files only, without delta-xfer algorithm which should reduce CPU load
# --no-compress as there's no lack of bandwidth between local devices
# --progress so I can see the progress of large files (optional)
alias modeler='modeler > /dev/null 2>&1 &'

alias bpython='python3 -m bpython'
alias lsblk='lsblk --fs'
alias inet='ip -c -h -br -a address'
alias reboot="sudo reboot"
alias scripts="code ~/workspace/personal/handy-scripts"

alias dock-mongo='docker run -d -p 27017:27017 --name mongo -v ~/data:/data/db mongo'
# mkdir ~/data && 
alias ip='curl -4 icanhazip.com'

# kubernetes
alias kgp="kubectl get pods"
alias k="kubectl"
alias kgd="kubectl get deployments"
alias kgs="kubectl get svc"
alias ka="kubectl apply -f"
alias kd="kubectl describe "
alias k-prod="kubectl config use-context do-lon1-speed-ensemble-prod"
alias k-stag="kubectl config use-context do-nyc1-speed-ensemble"


# file handling
alias rm='rm -i'
alias untar='tar -zxvf'
alias tar='tar -zcvf'



# Navigation
alias ..='cd ..'
alias ...='cd ../../'
alias ....='cd ../../../'
alias c="clear"

# Networking
alias ports='sudo netstat -tulanp'
alias ping='ping -c 5'
alias vpn='sudo openfortivpn -c /home/olalekan/workspace/workstuff/sterling/config'
alias vd='forticlient vpn disconnect'
alias vs='forticlient vpn status'

# git
alias gl='git log --oneline --graph --decorate' # display log of git in a graphical format
alias gpl="git pull"
alias gps="git pull && git push"
alias gs="git status"
alias gd="git diff"

# docker
alias docker-prune="docker system prune --all -f && docker volume prune -f"
alias docker-stop="docker stop $(docker ps -a -q)"
alias docker-rm="docker rm $(docker ps -a -q)"
alias docker-rmi="docker rmi $(docker images -a -q)"
alias purgeImages='docker rmi -f $(docker images -a -q)'
alias purgeContainers='docker rm -vf $(docker ps -a -q)'

