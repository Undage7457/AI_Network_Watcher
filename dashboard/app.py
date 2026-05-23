# =====================================================
# IMPORTS
# =====================================================

import streamlit as st
import pandas as pd
import socket
import json
import requests
import os
import sys

from pathlib import Path
from datetime import datetime
from sqlalchemy import text

# =====================================================
# PROJECT ROOT SETUP
# =====================================================

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

# =====================================================
# THIRD PARTY IMPORTS
# =====================================================

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

# =====================================================
# LOCAL IMPORTS
# =====================================================

from database.db import engine
from ai.detect_anomaly import detect_anomaly

# =====================================================
# LOAD ENVIRONMENT VARIABLES
# =====================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

# =====================================================
# STREAMLIT PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="AI Network Watcher",
    layout="wide"
)

st.title("📡 AI Network Watcher")

st.markdown(
    "### 🚀 Real-Time AI-Powered Wi-Fi Monitoring Dashboard"
)

# =====================================================
# DATABASE CONNECTION TEST
# =====================================================

try:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))

    st.success("✅ PostgreSQL Connected")

except Exception as e:
    st.error(f"❌ Database Connection Failed: {e}")

# =====================================================
# LOAD TRUSTED DEVICES
# =====================================================

TRUSTED_FILE = ROOT_DIR / "scanner" / "trusted_devices.json"

try:
    with open(TRUSTED_FILE, "r") as file:
        trusted_devices = json.load(file)

except Exception as e:
    st.error(f"❌ Failed to load trusted devices: {e}")
    trusted_devices = []

# =====================================================
# TELEGRAM ALERT FUNCTION
# =====================================================


def send_telegram_alert(message):

    if not BOT_TOKEN or not CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(
            url,
            data=payload,
            timeout=10
        )

    except Exception as e:
        st.error(f"Telegram Error: {e}")


# =====================================================
# AI DEVICE CLASSIFICATION
# =====================================================


def classify_device(hostname, vendor):

    hostname = str(hostname).lower()
    vendor = str(vendor).lower()

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
# =====================================================


def scan_network():

    try:

        # -------------------------------------------------
        # Auto Detect Local Network
        # -------------------------------------------------

        local_ip = socket.gethostbyname(
            socket.gethostname()
        )

        subnet = ".".join(
            local_ip.split(".")[:3]
        ) + ".0/24"

        target_ip = subnet

        st.info(f"🔍 Scanning Network: {target_ip}")

        # -------------------------------------------------
        # ARP Scan
        # -------------------------------------------------

        arp = ARP(pdst=target_ip)

        ether = Ether(
            dst="ff:ff:ff:ff:ff:ff"
        )

        packet = ether / arp

        result = srp(
            packet,
            timeout=5,
            verbose=0
        )[0]

        devices = []

        # -------------------------------------------------
        # Process Devices
        # -------------------------------------------------

        for sent, received in result:

            ip = received.psrc
            mac = received.hwsrc.lower()

            # ---------------------------------------------
            # Hostname Lookup
            # ---------------------------------------------

            try:
                hostname = socket.gethostbyaddr(ip)[0]

            except Exception:
                hostname = "Unknown"

            # ---------------------------------------------
            # Vendor Lookup
            # ---------------------------------------------

            try:
                vendor = MacLookup().lookup(mac)

            except Exception:
                vendor = "Unknown Vendor"

            # ---------------------------------------------
            # AI Device Classification
            # ---------------------------------------------

            device_type = classify_device(
                hostname,
                vendor
            )

            devices.append({

                "IP Address": ip,

                "MAC Address": mac,

                "Hostname": hostname,

                "Vendor": vendor,

                "Device Type": device_type
            })

        # -------------------------------------------------
        # Return DataFrame
        # -------------------------------------------------

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

    except Exception as e:

        st.error(f"❌ Scan Error: {e}")

        return pd.DataFrame()


# =====================================================
# SAVE DATA INTO POSTGRESQL
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

            "scan_time": datetime.now()
        })

    save_df = pd.DataFrame(records)

    try:

        save_df.to_sql(
            "device_logs",
            engine,
            if_exists="append",
            index=False
        )

    except Exception as e:

        st.error(f"❌ Database Insert Error: {e}")


# =====================================================
# AUTO REFRESH
# =====================================================

auto_refresh = st.checkbox(
    "Enable Auto Refresh (2 min)"
)

if auto_refresh:

    st_autorefresh(
        interval=120000,
        key="network_monitor"
    )

# =====================================================
# SCAN BUTTON
# =====================================================

scan_now = st.button("🔄 Scan Network")

if auto_refresh:
    scan_now = True

# =====================================================
# MAIN EXECUTION
# =====================================================

if scan_now:

    # -------------------------------------------------
    # Scan Network
    # -------------------------------------------------

    df = scan_network()

    # -------------------------------------------------
    # Device Count
    # -------------------------------------------------

    st.success(
        f"✅ Total Devices Found: {len(df)}"
    )

    # -------------------------------------------------
    # Save Into PostgreSQL
    # -------------------------------------------------

    save_to_database(df, trusted_devices)

    # -------------------------------------------------
    # Empty Check
    # -------------------------------------------------

    if df.empty:

        st.warning(
            "⚠️ No devices found on network"
        )

    else:

        # -------------------------------------------------
        # Detect Intruders
        # -------------------------------------------------

        intruders = df[
            ~df["MAC Address"].isin(
                trusted_devices
            )
        ]

        # -------------------------------------------------
        # Intruder Detection
        # -------------------------------------------------

        if len(intruders) > 0:

            st.error(
                "🚨 Intruder Devices Detected!"
            )

            st.dataframe(intruders)

            # -------------------------------------------------
            # Process Each Intruder
            # -------------------------------------------------

            for _, row in intruders.iterrows():

                # ---------------------------------------------
                # AI Anomaly Detection
                # ---------------------------------------------

                ai_result = detect_anomaly(

                    scan_hour=datetime.now().hour,

                    vendor=row["Vendor"],

                    device_type=row["Device Type"],

                    is_intruder=True
                )

                # ---------------------------------------------
                # Show AI Score
                # ---------------------------------------------

                st.warning(
                    f"🧠 AI Anomaly Score: "
                    f"{ai_result['score']:.4f}"
                )

                # ---------------------------------------------
                # Suspicious Detection
                # ---------------------------------------------

                if ai_result["anomaly"]:

                    st.error(
                        "🚨 AI DETECTED "
                        "SUSPICIOUS DEVICE"
                    )

                # ---------------------------------------------
                # Telegram Alert
                # ---------------------------------------------

                message = (

                    f"🚨 AI Security Alert!\n\n"

                    f"IP Address: "
                    f"{row['IP Address']}\n"

                    f"MAC Address: "
                    f"{row['MAC Address']}\n"

                    f"Vendor: "
                    f"{row['Vendor']}\n"

                    f"Device Type: "
                    f"{row['Device Type']}\n"

                    f"AI Anomaly Score: "
                    f"{ai_result['score']:.4f}\n"

                    f"Suspicious: "
                    f"{ai_result['anomaly']}"
                )

                send_telegram_alert(message)

        else:

            st.success(
                "✅ No intruders detected"
            )

        # -------------------------------------------------
        # Show Connected Devices
        # -------------------------------------------------

        st.subheader("📋 Connected Devices")

        st.dataframe(df)