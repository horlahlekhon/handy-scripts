
# ----------------------------------------------------------------------------------------------
# fix background themes issues in some themes where autosuggestion color is the same as command itself causing confusion... never add anything below this line
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=60'


# source ~/Documents/workspace/handy-scripts/dot-files/customs/.zsh-custom

SCRIPTS=~/workspace/personal/handy-scripts/dot-files/dotfiles

if [[ -d $SCRIPTS ]]; then
    for filename in $SCRIPTS/.* ; do
        if [[ $filename == *"tmux"* ]]; then
            # well, am sorry for not reloading this files, if you need to please do it manually for it is too expensve to do so everytime we load it
            # tmux source-file $filename
            elif [[ $filename == *"vimrc"* ]]; then
            # we are not loading vim too
        else
            source $filename
        fi
    done
fi

