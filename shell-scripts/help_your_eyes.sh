#!/bin/bash

# Author : Lekan Adebari
# Function : This wee script enables a pop up dialog to tell you if you have been gazing at your screen
#             for more than twenty minutes; scientifically,if you have been looking at your screen for
#            twenty minutes, it will help your eyes to look at a distance of 20 metres for 20 seconds
#            it is called the 20/20/20 rule
# Dependencies : zenity : zenity is used for the dialog
#                dbus-x11 : enables processes to talk to each other
#              this script run a cron job every 20 minutes so set up a cronjob with
#             edit your user crontab with : crontab -e
#              input this in the crontab :  `*/20 * * * * export DISPLAY=:0 && /path/to/this/file`
#



SHELL=/bin/bash

# kdialog --icon "/home/lekan/Documents/workspace/shell_scripts/index.jpeg" --geometry 500x500+300+300  --title "help your Eyes" --passivepopup "Yo! dawg! hold up  its been 20 minutes or you'd rather kill your eyes \n look at a distance of 20 metres for 20 minutes" timeout 5
export $(dbus-launch)
dbus-monitor --session "type='signal',interface='org.freedesktop.ScreenSaver'" |
while read x; do
    case "$x" in
        *"boolean true"*)
            echo SCREEN_LOCKED
            echo "this is locked xxxxxxxxxxx $x\n\n"
        break;;
        *"boolean false"*)
            echo SCREEN_UNLOCKED
            zenity --no-wrap --info --text "Yo! dawg! hold up its been <b>20 minutes</b>
or you'd rather kill your <b>eyes</b>. look at a
distance of <b>20 metres for 20 Seconds</b>
            "  > /dev/null 2>&1
            echo "this is unlocked  xxxxxxxxxxx $x\n\n"
        break;;
        *)
            echo "this is xxxxxxxxxxx $x\n\n"
            zenity --no-wrap --info --text "Yo! dawg! hold up its been <b>20 minutes</b>
or you'd rather kill your <b>eyes</b>. look at a
distance of <b>20 metres for 20 Seconds</b>
            "  > /dev/null 2>&1
            break
    esac
done