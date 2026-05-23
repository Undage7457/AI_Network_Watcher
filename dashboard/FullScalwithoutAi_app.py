# =====================================================
# IMPORTS
# =====================================================

import streamlit as st
import pandas as pd
import socket
import json
import requests
import os
from datetime import datetime

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))

from database.db import engine


# =====================================================
# LOAD ENVIRONMENT VARIABLES
# =====================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")


# =====================================================
# TELEGRAM ALERT FUNCTION
# Sends alerts to Telegram bot
# =====================================================

def send_telegram_alert(message):

    # Skip if credentials missing
    if not BOT_TOKEN or not CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(url, data=payload)

    except Exception as e:
        st.error(f"Telegram Error: {e}")


# =====================================================
# AI DEVICE CLASSIFICATION
# Predict device type using hostname/vendor
# =====================================================

def classify_device(hostname, vendor):

    hostname = hostname.lower()
    vendor = vendor.lower()

    if "desktop" in hostname:
        return "Windows PC"

    elif "android" in hostname:
        return "Android Phone"

    elif "iphone" in hostname:
        return "iPhone"

    elif "samsung" in vendor:
        return "Samsung Device"

    elif "xiaomi" in vendor:
        return "Android Phone"

    elif "apple" in vendor:
        return "Apple Device"

    elif "tenda" in vendor:
        return "Wi-Fi Router"

    elif "intel" in vendor:
        return "Laptop / PC"

    elif "dell" in vendor:
        return "Dell Laptop"

    elif hostname == "unknown":
        return "Unknown Network Device"

    else:
        return "Possible IoT Device"


# =====================================================
# NETWORK SCANNER
# Uses ARP scanning to detect active devices
# =====================================================

def scan_network():

    target_ip = "192.168.1.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    # Scan network
    result = srp(packet, timeout=8, verbose=0)[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc.lower()

        # Hostname lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # Vendor lookup
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown Vendor"

        # AI classification
        device_type = classify_device(hostname, vendor)

        devices.append({
            "IP Address": ip,
            "MAC Address": mac,
            "Hostname": hostname,
            "Vendor": vendor,
            "Device Type": device_type
        })

    # Debugging output
    st.write("Devices Raw Output:", devices)

    # Convert into DataFrame
    return pd.DataFrame(
        devices,
        columns=[
            "IP Address",
            "MAC Address",
            "Hostname",
            "Vendor",
            "Device Type"
        ]
    )


# =====================================================
# SAVE DATA INTO POSTGRESQL
# Stores device history for future AI analysis
# =====================================================

def save_to_database(df, trusted_devices):

    if df.empty:
        return

    records = []

    for _, row in df.iterrows():

        is_intruder = (
            row["MAC Address"] not in trusted_devices
        )

        records.append({
            "ip_address": row["IP Address"],
            "mac_address": row["MAC Address"],
            "hostname": row["Hostname"],
            "vendor": row["Vendor"],
            "device_type": row["Device Type"],
            "is_intruder": is_intruder,
            # Actual scan timestamp
            "scan_time": datetime.now()
        })

    save_df = pd.DataFrame(records)

    save_df.to_sql(
        "device_logs",
        engine,
        if_exists="append",
        index=False
    )


# =====================================================
# LOAD TRUSTED DEVICES
# =====================================================

with open("scanner/trusted_devices.json", "r") as file:
    trusted_devices = json.load(file)


# =====================================================
# STREAMLIT PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="AI Network Watcher",
    layout="wide"
)

st.title("📡 AI Network Watcher")

st.markdown("### 🚀 Real-Time Wi-Fi Monitoring Dashboard")


# =====================================================
# AUTO REFRESH CONFIGURATION
# Auto scans every 15 seconds
# Auto scans every 2 min
# =====================================================

auto_refresh = st.checkbox(
    "Enable Auto Refresh (30 sec)"
)

if auto_refresh:

    st_autorefresh(
        interval=30000,
        #interval=120000,
        key="network_monitor"
    )


# =====================================================
# SCAN BUTTON
# =====================================================

scan_now = st.button("🔄 Scan Network")


# =====================================================
# MAIN SCAN EXECUTION
# =====================================================

if scan_now or auto_refresh:

    # Scan network
    df = scan_network()

    st.success(f"✅ Total Devices Found: {len(df)}")

    # Save into PostgreSQL
    save_to_database(df, trusted_devices)

    # Empty check
    if df.empty:

        st.warning("⚠️ No devices found on network")

    else:

        # Detect intruders
        intruders = df[
            ~df["MAC Address"].isin(trusted_devices)
        ]

        # Intruder alerts
        if len(intruders) > 0:

            st.error("🚨 Intruder Devices Detected!")

            st.dataframe(intruders)

            # Send Telegram alerts
            for _, row in intruders.iterrows():

                message = (
                    f"🚨 Intruder Detected!\n"
                    f"IP Address: {row['IP Address']}\n"
                    f"MAC Address: {row['MAC Address']}\n"
                    f"Vendor: {row['Vendor']}\n"
                    f"Device Type: {row['Device Type']}"
                )

                send_telegram_alert(message)

        else:

            st.success("✅ No intruders detected")

        # Show device table
        st.subheader("📋 Connected Devices")

        st.dataframe(df)