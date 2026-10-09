import time
import requests
import re

# Paste your Slack webhook URL here
WEBHOOK_URL = ""

# The system log file where Linux records login attempts
LOG_FILE = "/var/log/secure"

print("Starting SSH monitoring.... ")

# Try to open the log file
try:
    log_file = open(LOG_FILE, "r")
except PermissionError:
    print("Error: You must run this script with sudo/root permissions!")
    exit(1)

# Move to the very end of the file so we only read NEW lines coming in
log_file.seek(0, 2)

# Keep running forever to watch the log in real time
while True:
    # Read the next line from the log file
    line = log_file.readline()
    
    # If there is no new line yet, wait 1 second and check again
    if not line:
        time.sleep(1)
        continue
        
    # Check for various types of SSH login failures (passwords, keys, or invalid users)
    failure_keywords = ["Failed password", "Failed publickey", "Invalid user"]
    
    if any(keyword in line for keyword in failure_keywords):
        print(f"Alert! Found a failed login attempt: {line.strip()}")
        
        # Build the message payload for Slack
        payload = {
            "text": f"🚨 *SSH Login Failure Detected!*\n```\n{line.strip()}\n```"
        }
        
        # Send the alert to Slack using the requests library
        try:
            response = requests.post(WEBHOOK_URL, json=payload)
            
            if response.status_code == 200:
                print("Slack alert sent successfully!")
            else:
                print(f"Failed to send Slack alert. Status code: {response.status_code}")
                
        except Exception as e:
            print(f"Network error when trying to reach Slack: {e}")
