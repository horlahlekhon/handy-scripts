#!/bin/bash

cur_time=$(date --utc +%s)

help_your_eyes(){
    while true ; do
        time=$(date --utc +%s)
        diff=$(($time - $cur_time))
        if [ $diff ==  5 ]; then
            cur_time=$(date --utc +%s)
            min=$(($diff / 60))
            #  uncomment below line in the case of a different DE than KDE
            # notify-send -u critical -i info 'Yo! dawg! hold up ' " its been '$(($diff / 60))' minutes or you'd rather kill your eyes \n look at a distance of 20 metres for 20 minutes"
            
            # Zenity has some good kungfu dialog, you can check it out
            # zenity  --warning --text "Yo! dawg! hold up its been $min minutes or you'd rather kill your eyes. look at a distance of 20 metres for 20 minutes"
            
            # comment this line out if you are using a different DE than KDE
            kdialog --icon "/home/lekan/Documents/workspace/shell_scripts/index.jpeg" --geometry 500x500  --title "help your Eyes" --passivepopup "Yo! dawg! hold up  its been '$(($diff / 60))' minutes or you'd rather kill your eyes \n look at a distance of 20 metres for 20 minutes" timeout
            
        fi
        echo "current time == $time"
        echo "prodigal time == $cur_time"
        echo "not yet time : differrebce == $diff"
    done
}
echo "i ran"
help_your_eyes
# dbus-monitor --session "type='signal',interface='org.freedesktop.ScreenSaver'" |
# while read x; do
#     case "$x" in
#         *"boolean true"*) echo SCREEN_LOCKED;;
#         *"boolean false"*) 
#           echo SCREEN_UNLOCKED
#           help_your_eyes
#           echo "ran help your eyes"
#         ;;
#     esac
# done