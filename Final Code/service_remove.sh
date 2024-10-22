#!/bin/bash

# Get the username
echo "Enter your username:"
read username

# Stop the service
sudo systemctl stop email_fetchncheck.service

# Disable the service from starting at boot
sudo systemctl disable email_fetchncheck.service

# Remove the service file
sudo rm /etc/systemd/system/email_fetchncheck.service

# Reload the systemd daemon
sudo systemctl daemon-reload

# Check if the service has been removed
sudo systemctl status email_fetchncheck.service