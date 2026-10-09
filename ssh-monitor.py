

import time
import re
import ipaddress
import requests

# Paste your Slack webhook URL here
WEBHOOK_URL = ""
# The system log file where Linux records login attempts
LOG_FILE = "/var/log/secure"

# Each (IP + username) combination only alerts ONCE within this many seconds (600 = 10 minutes)
COOLDOWN_SECONDS = 600

# Safety limit: max alerts for a single IP within the cooldown, so a bot trying
# hundreds of usernames can't flood your Slack channel
MAX_ALERTS_PER_IP = 5

# Words that mean "someone failed to log in"
FAILURE_KEYWORDS = ["Failed password", "Failed publickey", "Invalid user"]

# Finds the IP address in a log line, e.g. "... from 203.0.113.5 port 52114 ssh2"
IP_PATTERN = re.compile(r"\bfrom\s+([0-9a-fA-F:.]+)")

# Finds the username, e.g. "Failed password for invalid user admin from ..." -> admin
USER_PATTERN = re.compile(r"(?:Invalid user|for(?: invalid user)?)\s+(\S+)\s+from\s+", re.IGNORECASE)

last_alert_time = {}   # ip -> when we last alerted about it
location_cache = {}    # ip -> location text (saves repeated lookups)


def extract_ip(line):
    """Return the IP address found in a log line, or None."""
    match = IP_PATTERN.search(line)
    if not match:
        return None
    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def extract_username(line):
    """Return the username that was tried, made safe to show in Slack."""
    match = USER_PATTERN.search(line)
    if not match:
        return "unknown"

    # The username is typed by the attacker, so clean it before posting it
    name = match.group(1)
    name = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")
    return name[:64]


def should_alert(ip, username):
    """Decide if this attempt deserves a Slack alert.

    Returns (send, last_one):
      send     - True if we should send an alert
      last_one - True if this is the final alert allowed for this IP right now
    """
    now = time.time()

    # Forget old entries so the dictionary doesn't grow forever
    for old_key in [k for k, t in last_alert_time.items() if now - t > COOLDOWN_SECONDS]:
        del last_alert_time[old_key]

    key = (ip, username)

    # Same IP + same username already reported recently (this also covers the
    # duplicate log lines a single login attempt creates)
    if key in last_alert_time:
        return False, False

    # Too many alerts from this IP already
    alerts_for_ip = sum(1 for (known_ip, _) in last_alert_time if known_ip == ip)
    if alerts_for_ip >= MAX_ALERTS_PER_IP:
        return False, False

    last_alert_time[key] = now
    return True, (alerts_for_ip + 1 == MAX_ALERTS_PER_IP)


def geolocate(ip):
    """Look up city / region / country / ISP for an IP (free service, no API key)."""
    if ip in location_cache:
        return location_cache[ip]

    # Private or local addresses (192.168.x.x, 10.x.x.x ...) can't be geolocated
    if not ipaddress.ip_address(ip).is_global:
        result = ("Local / private network", None)
    else:
        try:
            data = requests.get(f"https://ipwho.is/{ip}", timeout=5).json()
            if data.get("success"):
                parts = [data.get("city"), data.get("region"), data.get("country")]
                place = ", ".join(p for p in parts if p) or "Unknown"
                isp = (data.get("connection") or {}).get("isp")
                result = (place, isp)
            else:
                result = ("Unknown", None)
        except Exception as e:
            print(f"Geolocation lookup failed: {e}")
            return ("Unknown", None)  # don't cache failures, try again next time

    location_cache[ip] = result
    return result


def send_slack_alert(ip, username, last_one=False):
    """Send a short, clean alert to Slack."""
    place, isp = geolocate(ip)

    text = (
        "🚨 *Someone is trying to log in to your server via SSH*\n"
        f"📍 *IP:* `{ip}`\n"
        f"👤 *Username tried:* `{username}`\n"
        f"🌍 *Location:* {place}"
    )
    if isp:
        text += f"\n🏢 *ISP:* {isp}"
    if last_one:
        text += "\n🔇 _Many attempts from this IP - further alerts for it are muted for a while._"

    try:
        response = requests.post(WEBHOOK_URL, json={"text": text}, timeout=10)
        if response.status_code == 200:
            print(f"Slack alert sent for {ip}")
        else:
            print(f"Failed to send Slack alert. Status code: {response.status_code}")
    except Exception as e:
        print(f"Network error when trying to reach Slack: {e}")


def main():
    print("Starting simple SSH security monitor...")

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
        line = log_file.readline()

        # If there is no new line yet, wait 1 second and check again
        if not line:
            time.sleep(1)
            continue

        # Ignore anything that isn't a login failure
        if not any(keyword in line for keyword in FAILURE_KEYWORDS):
            continue

        ip = extract_ip(line)
        if ip is None:
            continue

        username = extract_username(line)

        # One alert per IP + username, no matter how many log lines it creates
        send, last_one = should_alert(ip, username)
        if not send:
            continue

        print(f"Failed login attempt from {ip} (username: {username})")
        send_slack_alert(ip, username, last_one)


if __name__ == "__main__":
    main()