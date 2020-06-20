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
alias postman='postman > /dev/null 2>&1 &'
alias uml='umlet'
alias cp='rsync --progress --no-compress -rhaHAXv'
# Rsync options
# -a is for archive, which preserves ownership, permissions etc.
# -v is for verbose, so I can see what's happening (optional)
# -h is for human-readable, so the transfer rate and file sizes are easier to read (optional)
# -W is for copying whole files only, without delta-xfer algorithm which should reduce CPU load
# --no-compress as there's no lack of bandwidth between local devices
# --progress so I can see the progress of large files (optional)
alias modeler='modeler > /dev/null 2>&1 &'
alias 'conda-nav'='cd ~/anaconda3/bin && ./anaconda-navigator > /dev/null 2>&1 &'
alias charm='pycharm > /dev/null 2>&1 &'
alias storm='webstorm > /dev/null 2>&1 &'
alias grip='datagrip > /dev/null 2>&1 &'
alias bpython='python3 -m bpython'
alias zoo='/usr/local/kafka_2.12-2.3.0/bin/zookeeper-server-start.sh /usr/local/kafka_2.12-2.3.0/config/zookeeper.properties  '
alias kafka='/usr/local/kafka_2.12-2.3.0/bin/kafka-server-start.sh /usr/local/kafka_2.12-2.3.0/config/server.properties   '
alias lsblk='lsblk --fs'
alias inet='ip -c -h -br -a address'
alias reboot="sudo reboot"
alias scripts="code ~/Documents/workspace/handy-scripts"
alias mongui="pushd . && cd ~/.local/bin && ./mongui > /dev/null 2>&1 &"
alias fire-night="pushd . && fire > /dev/null 2>&1 &"
alias inst_cuda='sudo aptitude install nvidia-cuda-toolkit nvidia-opencl-icd'


# aliases specific to ubanquity
alias pg-camunda='pgcli -U ubanquity -d camunda -p 5433'
alias pg-dwh='pgcli -U ubanquity -d dwh_zenith -p 5433'
alias pg-esusu='pgcli -U ubanquity -d esusu -p 5432'
alias pg-core='pgcli -U ubanquity -d core -p 5432'
alias pg-postgres='pgcli -U postgres -d postgres -p 5432'
alias pg-finance='pgcli -U ubanquity -d finance -p 5433'
alias uba='sudo openfortivpn -c ~/openfortivpn.conf'



#aliases specific to demz analytics
alias whatsapp='cd $DEEP_TEST && sbt wsWhatsappMonitoring/run '
alias deep-proc='cd $DEEP_TEST && sbt dataProcessing/run '
alias deep-mine='cd $DEEP_TEST && sbt dataMining/run '
alias deep-front='cd $DEEP_FRONT && npm run start'




