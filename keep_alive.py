#!/usr/bin/env python3
"""
Keep-alive script for Render free tier apps.
Pings the app at random intervals (5-9 minutes) to prevent sleep.
Run this on a separate server, local machine, or GitHub Actions.
"""

import requests
import time
import random
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Your Render app URL (replace with actual URL after deployment)
APP_URL = "https://your-app-name.onrender.com"

# Health check endpoint (lightweight)
PING_ENDPOINT = f"{APP_URL}/api/stats"

# Ping interval range (in seconds)
MIN_INTERVAL = 5 * 60   # 5 minutes
MAX_INTERVAL = 9 * 60   # 9 minutes

def ping_app():
    """Send a lightweight request to keep the app alive."""
    try:
        response = requests.get(PING_ENDPOINT, timeout=30)
        if response.status_code == 200:
            logger.info(f"✅ Ping successful - Status: {response.status_code}")
            return True
        else:
            logger.warning(f"⚠️ Ping returned status: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Ping failed: {e}")
        return False

def main():
    """Main keep-alive loop."""
    logger.info(f"🚀 Starting keep-alive for {APP_URL}")
    logger.info(f"📊 Ping interval: {MIN_INTERVAL//60}-{MAX_INTERVAL//60} minutes")
    
    while True:
        try:
            # Ping the app
            ping_app()
            
            # Calculate next ping time (random interval)
            next_interval = random.randint(MIN_INTERVAL, MAX_INTERVAL)
            next_ping = datetime.now().strftime("%H:%M:%S")
            logger.info(f"⏰ Next ping in {next_interval//60}m {next_interval%60}s")
            
            # Sleep until next ping
            time.sleep(next_interval)
            
        except KeyboardInterrupt:
            logger.info("🛑 Keep-alive stopped by user")
            break
        except Exception as e:
            logger.error(f"💥 Unexpected error: {e}")
            # Wait 1 minute before retrying
            time.sleep(60)

if __name__ == "__main__":
    main()
