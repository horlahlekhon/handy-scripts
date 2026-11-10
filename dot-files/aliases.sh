#!/bin/bash
# Aliases. Sourced by dot-files/bashrc.

# ls
alias ll='ls -l'
alias la='ls -Alh'
alias l='ls -CF'

# navigation
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias c='clear'

# system
alias lsblk='lsblk --fs'
alias inet='ip -c -h -br address'
alias myip='curl -4 -s icanhazip.com'
alias ports='sudo ss -tulpn'
alias ping='ping -c 5'
alias reboot='sudo reboot'
alias scripts='code "$HANDY_SCRIPTS"'

# files
alias rm='rm -i'
alias targz='tar -zcvf'
alias untar='tar -zxvf'

# git
alias gl='git log --oneline --graph --decorate'
alias gs='git status'
alias gd='git diff'
alias gpl='git pull'
alias gps='git pull && git push'

# docker (single quotes: substitution must run at call time, not at shell start)
alias docker-prune='docker system prune --all -f && docker volume prune -f'
alias docker-stop='docker stop $(docker ps -q)'
alias docker-rm='docker rm $(docker ps -a -q)'
alias docker-rmi='docker rmi $(docker images -a -q)'
alias purgeImages='docker rmi -f $(docker images -a -q)'
alias purgeContainers='docker rm -vf $(docker ps -a -q)'
alias dock-mongo='mkdir -p ~/data && docker run -d -p 27017:27017 --name mongo -v ~/data:/data/db mongo'
