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
alias la='ls -A'
alias l='ls -CF'


alias goedit='goedit > /dev/null 2>&1 &'
alias idea='idea > /dev/null 2>&1 &'
alias postman='postman > /dev/null 2>&1 &'
alias uml='umlet'
alias cp='rsync --progress -r'
alias modeler='modeler > /dev/null 2>&1 &'
alias 'conda-nav'='cd ~/anaconda3/bin && ./anaconda-navigator > /dev/null 2>&1 &'
alias charm='pycharm > /dev/null 2>&1 &'
alias uba='sudo openfortivpn -c ~/openfortivpn.conf'
alias bpython='python3 -m bpython'



# database aliases
alias pg-camunda='pgcli -U ubanquity -d camunda -p 5433'
alias pg-dwh='pgcli -U ubanquity -d dwh_zenith -p 5433'
alias pg-esusu='pgcli -U ubanquity -d esusu -p 5432'
alias pg-core='pgcli -U ubanquity -d core -p 5432'
alias pg-postgres='pgcli -U postgres -d postgres -p 5433'
alias pg-finance='pgcli -U ubanquity -d finance -p 5433'

