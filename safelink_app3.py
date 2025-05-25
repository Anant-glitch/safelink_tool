import streamlit as st
import requests
from googlesearch import search

# Load API Key from secrets
GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]

# Function to check URL with Google Safe Browsing API
def is_url_malicious(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    body = {
        "client": {
            "clientId": "safelink-lite",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(endpoint, json=body)
    if res.status_code == 200:
        return "matches" in res.json()
    return False

# Trusted software sources
trusted_sources = {
    "vlc": "videolan.org",
    "winrar": "win-rar.com",
    "chrome": "google.com",
    "adobe reader": "adobe.com",
    "anydesk": "anydesk.com",
    "notepad++": "notepad-plus-plus.org",
    "firefox": "mozilla.org",
    "7zip": "7-zip.org",
    "visual studio code": "code.visualstudio.com",
    "python": "python.org"
}

# UI setup
st.markdown("<h1 style='text-align: center;'>🔐 SafeLink Lite – Secure Download Scanner</h1>", unsafe_allow_html=True)
software = st.text_input("🔍 Enter software name (e.g., VLC, WinRAR, Chrome):")

if st.button("Search"):
    st.info(f"Searching for: {software}")
    links = list(search(f"{software} download", num_results=5))

    for link in links:
        if any(source in link for source in trusted_sources.values()):
            st.success(f"✅ Trusted: {link}")
        elif is_url_malicious(link):
            st.error(f"🚫 Malicious: {link}")
        else:
            st.warning(f"⚠️ Unverified: {link}")
