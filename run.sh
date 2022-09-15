#!/bin/bash

## Edit the values and run the script to test your teams webhook

webhookUrl=""

python3 custom-teams.py "example-alert.json" "" "${webhookUrl}" " > /dev/null 2>&1" "DEBUG"
