#!/bin/bash
#===============================================================================
#
#          FILE: .bash_functions.sh
#
#         USAGE: source .bash_functions
#
#   DESCRIPTION: This files containsfunctions that provide handy utitlities for manipulating verbose tasks
#                    as well as functions that i use to automate things like setting up a project and other trivial stuffs
#
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Olalekan Adebari
#  ORGANIZATION:
#       CREATED: 17/11/2019 03:23
#      REVISION:  ---
#===============================================================================

#set -o nounset                              # Treat unset variables as an error





# this function basically runs python projects and creates environment on the fly if it doesnt yet exist. it will also opens vscode or a text editor
# that is specified in $EDITOR

py() {
    PROJ=$1
    if [[ $EDITOR == "" ]] ; then
        EDITOR='code'
    fi
    
    if [ -d $PROJ ] ; then
        cd $PROJ
        if [[ $(ls ../ | grep bin)  == "bin" ]] ; then
            
            echo "Sourcing and activating your environment"
            source ../bin/activate
            echo "opening virtual studio code for your convenience"
            eval $EDITOR .
            elif [[  $( ls | grep bin) == "bin" ]] ; then
            echo "Sourcing and activating your environment, but your environment and your project are on the same folder"
            source bin/activate
            echo "opening virtual studio code for your convenience"
            eval $EDITOR .
            elif [[ $( ls | grep "bin") != "bin" || -d $PROJ && $(ls ../ | grep bin) == "bin"  ]] ; then
            
            echo "$PROJ does not have a virtual environment created"
            echo " would you like to create it ?. y/n"
            read ANS
            if [ $ANS == "y" ]; then
                echo "would you prefer python 3 or 2 enter the number please."
                read PYVERSION
                if [[ $PYVERSION == "2" || $PYVERSION == "3" ]] ;  then
                    if [ $( dpkg -l | grep virtualenv | awk '{print$2}' | grep ^virtualenv) == "virtualenv" ]; then
                        echo "creating a virtual environment for your project with python version $PYVERSION \\n and the current directory name as the environment name"
                        ENV_NAME="$( pwd | tr / \\t | awk '{print $(NF)}')_env"
                        ENV_INTERMEDIATE_DIR=..
                        ENV_DIR=$ENV_INTERMEDIATE_DIR/$ENV_NAME
                        cd $ENV_INTERMEDIATE_DIR
                        virtualenv -p "python$PYVERSION" $ENV_NAME
                        mv $PROJ $ENV_NAME
                        cd $ENV_NAME
                        source bin/activate
                        eval $EDITOR .
                    else
                        echo "virtualenv is not installed, kindly install with appropriate package manager and retry "
                    fi
                else
                    echo "wrong python version : $PYVERSION"
                fi
            else
                echo "thanks, we shall open your code with visual code"
            fi
        else
            echo "the paths passed is not a directory"
        fi
    else
        echo "the paths passed is not a directory"
    fi
    
}



# this function reimplement `cd` so that when we move to a directory , it automatically list the files
function cd() {
    DIR="$*";
    # if no DIR given, go home
    if [ $# -lt 1 ]; then
        DIR=$HOME;
    fi;
    builtin cd "${DIR}" && \
    # use your preferred ls command
    ls -F --color=auto
}


# get the program runnning on  a port
function port(){
    sudo netstat -nlp | grep "$1"
}

#du: It’s a command
#-h: Print sizes in human readable format (e.g., 1K, 234M, 2G)
#-c: Produce a grand total
#/home/path/directory/: The path of directory
#sort -rh: Sort the results with numerical value
#head -2: Output the first 2 lines result which is basically the size of the directory itself and the grand total of all files and directories in it
#--max-depth=0 : dont show the subdirectories
function dsize(){
    #du -hc '$1' | sort -rh | head -2
    du -h --max-depth=0 "$1"
}


function storage-mode(){
    if [[ $1 == 'nfs' ]] ; then
        export STORAGE_MODE=nfs
        export LOCAL_BUCKET=/home/lekan/Desktop/smc-v1-dev
        export LOCAL_MEDIA_FOLDER=media
        export encryption_key=dev_key
        elif [[ $1 == 'googleStorage' ]] ; then
        export STORAGE_MODE=googleStorage
        export bucket=smc-v1-dev
        export media_folder=media
        export encryption_key=dev_key
    else
        echo 'Please enter a storage type to use'
    fi
    
}
# source the custom bash functions
source ~/Documents/workspace/handy-scripts/dot-files/customs/.custom-bash_functions

# improve this function to check if kafka and zookeeper is up or not by checking the ports
function removeTopic(){
    cd $KAFKA_HOME > /dev/null
    ./kafka-topics.sh --zookeeper localhost:2181 --delete --topic $1
}

# TODO improve to detect when a topic is present and that kafka is on
# This works by setting the data retention time of kafka, the default is 604800000ms
# so we just set the retention to 1ms and wait for 1s by that time the messages will have been deleted and we
#  set the retention back to default
function purgeTopic(){
    cd $KAFKA_HOME > /dev/null
    ./kafka-topics.sh --zookeeper localhost:2181 --alter --topic $1 --config retention.ms=1000
    sleep 1
    ./kafka-topics.sh --zookeeper localhost:2181 --alter --topic $1 --config retention.ms=604800000
    
}

function pg(){
    if [[ $1 == "stop" ]]; then
        sudo pg_ctlcluster 11 main stop
    else
        sudo pg_ctlcluster 11 main start
    fi
}