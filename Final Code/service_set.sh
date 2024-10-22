#!/bin/bash

# Get the username
echo "Enter your username:"
read username

# Get the current working directory
script_path=$(pwd)/real_time_interval.py

# Create the service file
cat <<EOT > /etc/systemd/system/email_fetchncheck.service
[Unit]
Description=Email Fetch and Check Service
After=network.target

[Service]
User=$username
ExecStart=/usr/bin/python $script_path
Restart=always

[Install]
WantedBy=multi-user.target
EOT

# Reload the systemd daemon
sudo systemctl daemon-reload

# Enable the service to start at boot
sudo systemctl enable email_fetchncheck.service

# Start the service immediately
sudo systemctl start email_fetchncheck.service

# Check the status of the service
sudo systemctl status email_fetchncheck.service