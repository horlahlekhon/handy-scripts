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
    ls -F
}


# get the program runnning on  a port
function port(){
    SYSTEM_INFO=$(uname -a )
    if [[ $SYSTEM_INFO == *"Darwin"* ]]; then
        lsof -nP -iTCP:$1 | grep LISTEN
    else
        sudo netstat -nlp | grep "$1"
    fi
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


# source the custom bash functions
# source ~/Documents/workspace/handy-scripts/dot-files/customs/.custom-bash_functions

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
    SYSTEM_INFO=$(uname -a )
    if [[ $1 == "stop" ]]; then
        if [[ $SYSTEM_INFO == *"Darwin"* ]]; then
            pg_ctl -D /usr/local/var/postgres stop 
        else
            sudo pg_ctlcluster 11 main stop
        fi
    else
        if [[ $SYSTEM_INFO == *"Darwin"* ]]; then
            pg_ctl -D /usr/local/var/postgres start 
        else
             sudo pg_ctlcluster 11 main start
        fi
    fi
}

function ctx(){
    if [[ $1 == "prod" || $1 == "production" || $1 == "prd" || $1 == "p" ]]; then
        kubectl config use-context do-lon1-speed-ensemble-prod
        kubectl config set-context "$(kubectl config current-context)" --namespace=pilot
    elif [[ $1 == "stag" || $1 == "stage" || $1 == "staging" || $1 == "s" ]]; then
        kubectl config use-context do-nyc1-speed-ensemble
        kubectl config set-context "$(kubectl config current-context)" --namespace=staging
    elif [[ $1 == "beta" || $1 == "bet" || $1 == "b" || $1 == "be" ]]; then
        kubectl config use-context do-nyc1-speed-ensemble-beta
        kubectl config set-context "$(kubectl config current-context)" --namespace=beta
    else
        printf  "Cannot determine the context to change to from the following available contexts \n" 
        kubectl config get-contexts
    fi
}

function some_postgres(){
    # STRT=$(docker start some-postgres)
    if [[ ! $(docker start some-postgres) ]]; then
        echo "oops.. no db instance, but dont fret; starting a new instance for you"
        docker run --name some-postgres -e POSTGRES_PASSWORD=admin -p 5432:5432 -d postgres || exit 2
        echo "Postgres instance started... your password is 'admin' with user 'postgres'"
    else
        echo "cool.. peace out"
    fi
}

function kexec(){
    pod=$1
    k exec -it "$pod" -- /bin/sh -c bash -il
}

# AWS
logs(){
    service=$1
    start=$2
    now=$(date +%s%3N)
    filter_pattern=$3
    
    start_ts=$(date -d "$start hours ago" +%s%3N)
    # /ecs/monetary-service-consumer
    if [ "$service" = "events" ]; then
        group_name="/ecs/maraboo-transaction-event-consumer"
    elif [ "$service" = "api" ]; then
        group_name="/ecs/maraboo-api"
    elif [ "$service" = "consumer" ]; then
        group_name="/ecs/monetary-service-consumer"
    elif [ "$service" = "collections" ]; then
        group_name="/ecs/mb-collections"
    elif [ "$service" = "payments" ]; then
        group_name="/ecs/mb-payments"
    else
        echo "Valid Service name was not provided: $service"
        exit 1
    fi
    echo "Searching logs from $start hour(s) ago for pattern: $filter_pattern on $group_name"

    aws logs filter-log-events --log-group-name "$group_name"  --query 'events[*].[timestamp,logStreamName,message]' --start-time "$start_ts" --end-time "$now" --filter-pattern "$filter_pattern" --output text
}

tail(){
    service=$1
    since=$2
    pattern=$3
    if [ "$service" = "events" ]; then
        group_name="/ecs/maraboo-transaction-event-consumer"
    elif [ "$service" = "api" ]; then
        group_name="/ecs/maraboo-api"
    elif [ "$service" = "consumer" ]; then
        group_name="/ecs/monetary-service-consumer"
    elif [ "$service" = "collections" ]; then
        group_name="/ecs/mb-collections"
    elif [ "$service" = "payments" ]; then
        group_name="/ecs/mb-payments"
    else
        echo "Valid Service name was not provided: $service"
        exit 1
    fi
    if [[ $since =~ ^-?[0-9]+$ ]]; then
        since=$since
    else
        since=1
    fi
    echo "Tailing logs from $since hour(s) ago, searching for pattern: $filter_pattern on $group_name"

    aws logs tail "$group_name" --filter-pattern "$pattern" --since "${since}h"  --output text --follow
}


restart_ecs(){
    service=$1
    aws ecs update-service \
    --cluster your-cluster-name \
    --service your-service-name \
    --task-definition your-task-family:revision \
    --force-new-deployment
}