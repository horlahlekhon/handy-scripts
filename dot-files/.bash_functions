
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



function cl() {
    DIR="$*";
        # if no DIR given, go home
        if [ $# -lt 1 ]; then
                DIR=$HOME;
    fi;
    builtin cd "${DIR}" && \
    # use your preferred ls command
        ls -F --color=auto
}


function port(){
    sudo netstat -nlp | grep "$1"
}