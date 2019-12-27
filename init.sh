#!/bin/zsh 

setupZsh() {
    echo "Lets set up your zsh and oh-my-zsh. Caveat : Please make sure you are connected to the internet"
    sudo apt-get install wget curl git
    sudo apt install zsh

    if [[ $? == "0" ]]; then 
        echo "Now lets set default shell to be zsh"
        cp dot-files/.zshrc ~/
        chsh -s $(which zsh)

        echo "Installing oh-my-zsh"
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

        if [[ $? == "0" ]]; then
            echo "Would you like me to install zsh auto-completion and syntax highligtings Y/N"
            read COMP 
            if [[ $COMP == "y" ]]; then 
                git clone git://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
                git clone https://github.com/zsh-users/zsh-history-substring-search ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-history-substring-search
                git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
                echo "Please carefully activate the plugin by adding `zsh-autosuggestions zsh-history-substring-search zsh-syntax-highlighting` at the end of the \n activated plugings list in ~/Documents/workspace/handy-scripts/dot-files/.zshrc"
                echo "please note that all customizations for zsh should be made to  ~/Documents/workspace/handy-scripts/dot-files/.zsh-custom instead of modifying the .zshrc directly. \n please restart your terminal"
            fi
            echo "Now you are ready to go, you will need to logout and relogin to activate the juice, you can do it later , if you still have some other things to do now"
            # echo "Would you like to logout now ? Y/N"
            # read LOGOUT
            # if [[ $LOGOUT == "y" ]]; then
        else 
            echo "Something went wrong installing oh-my-zsh... please fix and rerun the script"
        fi
    else
        echo "Something went wrong with the initial package verification, kindly fix and rerun the script"
    fi
}

echo "First and foremost... the world is moving away from ASCII... lets move too... changing locale to utf-8.... please pardon us.. re-run this file after this reboot"
LANG_CHECK= tr \\0 \\n < /proc/$PPID/environ | egrep '^(LANG|LC_)' | gawk -F= '{split($0,s,"="); print s[2]}'
if [[ $LANG_CHECK == *"en_US.UTF-8"* ]]; then 
    echo "Oh! you are already a utf-8 coder !! lets move on"
else 
    # update locale to utf-8 to support unicode codepoints
    sudo update-locale LANG=en_US.UTF-8 LANGUAGE=en.UTF-8
    sudo reboot

echo "lets do some set up first to make sure required packages exists"
sudo apt install tmux curl wget
echo "Hello! champion! Should i set up Zsh and oh-my-zsh or you are going back to your first love ; the bourn shell ? \n (1) Zsh \n (2) keep bash"
read DEFBASH

if [[ DEFBASH == "1" ]]; then 
    setupZsh
else 
    echo "Happy bashing"
fi
