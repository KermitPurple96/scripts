#!/bin/bash 

old_process=$(ps -eo command)

while true; do
  new_process=$(ps -eo command)
  diff <(echo "$old_process") <(echo "$new_process") |grep [\<\>] | grep -vE "command|procmon"
  old_process=$new_process
done
