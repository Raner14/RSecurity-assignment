# RSecurity Internship Assignment - Security Log Analyzer

**Part 3: Security/Analysis – Detect Suspicious Activity**

---

## Assignment Overview

This project analyzes raw activity logs (CSV format) and detects suspicious behaviors that may indicate security incidents. The system implements **5 detection algorithms** covering different attack vectors as specified in the assignment requirements.

**Input:** `timestamp, user_id, action, ip_address`  
**Output:** JSON report with detected anomalies + professional visualization

---

## Project Structure

```
rsecurity-assignment/
├── data/
│   └── sample_logs_no_status.csv    # Input log file (provided)
├── geoip/
│   └── GeoLite2-Country.mmdb        # GeoIP database (download required)
├── outputs/
│   ├── anomalies.json               # Detection results
│   └── anomaly_analysis.png         # Hourly threat visualization
├── src/
│   └── analyze.py                   # Main analysis engine
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore rules
└── README.md                        # This documentation
```

---

## How to Run

### Step 1: Install Dependencies
```bash
# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows

# Install required packages
pip install -r requirements.txt
```

### Step 2: Download GeoIP Database
**REQUIRED:** This project needs the MaxMind GeoLite2-Country database for geographic analysis.

1. **Register** (free): [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. **Download**: GeoLite2-Country database (Binary .mmdb format)
3. **Place at**: `geoip/GeoLite2-Country.mmdb`

### Step 3: Run Analysis
```bash
python src/analyze.py

# Expected output:
# Total anomalies detected: X
# Results saved to: outputs/anomalies.json
# Visualization saved to: outputs/anomaly_analysis.png
```

---

## Detection Methods

The system implements **5 detection algorithms** covering different attack vectors commonly seen in real-world scenarios:

### 1. Brute-Force Detection
**What it detects:** Multiple failed login attempts from same IP targeting same user

**Why this approach:**  
Classic credential stuffing attack where attacker systematically tries passwords against one specific account. This is different from password spraying because it focuses on breaking into one target.

**Detection logic:**  
- Groups events by `(ip_address, user_id)` combinations
- Uses sliding window algorithm to detect 5 or more failures within 10 minutes  
- Efficient implementation with two-pointer technique

**Real-world scenario:** Attacker targets "admin" account and tries common passwords like "password123", "admin", "123456" repeatedly from IP 203.0.113.200.

```python
# Configuration in analyze.py
BRUTEFORCE_THRESHOLD = 5    # Failed attempts to trigger alert
BRUTEFORCE_WINDOW_MIN = 10  # Time window (minutes)
```

### 2. Suspicious IP Detection  
**What it detects:** Account takeover from new external IPs with suspicious activity patterns

**Why this sophisticated approach:**  
Simple "new IP" detection creates massive false positives (remote work, mobile networks, VPNs). Instead, we use **dual-condition logic** that only flags IPs that are BOTH:
1. **First-time use** by this user (greater than 60 day gap)  
2. **Recently failed** attempts from same IP (within 60 minutes)

**Detection logic:**  
- Only analyzes **public IP addresses** (ignores internal 10.x.x.x, 192.168.x.x)
- Tracks historical IP usage per user with 60-day lookback
- Correlates successful logins with recent failed attempts from same IP
- **Daily deduplication** prevents alert spam for same (user,IP) pair

**Real-world scenario:** Attacker compromises "alice" account, logs in from new IP 151.101.1.69. That IP had failed login attempts 20 minutes earlier (reconnaissance phase), then succeeded (compromise phase).

**Why it works:** Legitimate remote access rarely involves failed attempts followed by success from same new IP within short timeframe.

### 3. Geographic Impossible Travel (Geo-hops)
**What it detects:** Same user appearing in different countries within physically impossible timeframe

**Why this approach:**  
Human users cannot travel between countries in minutes. When we see this pattern, it almost always indicates account compromise where attacker and legitimate user are active simultaneously.

**Detection logic:**  
- Resolves IP addresses to countries using MaxMind GeoLite2 database
- Groups events by `user_id`, sorts chronologically  
- Flags country changes within 5 minutes (physically impossible)
- Handles edge cases: unknown countries, same-country travel

**Real-world scenario:** User "user16" logs in from Germany at 09:00, then appears logging in from South Korea at 09:04. Even fastest flights take 10+ hours between these locations.

**Technical note:** Uses `geoip2` library with local MMDB database for fast, privacy-preserving lookups.

### 4. Password Spraying Detection
**What it detects:** Single IP attempting to compromise multiple user accounts (opposite of brute-force)

**Why this approach:**  
Modern attackers avoid brute-force (triggers account lockouts) and instead use "low and slow" approach: try one common password against many accounts. This flies under traditional detection radar.

**Detection logic:**  
- Groups events by `ip_address` (attacker perspective)
- Within 15-minute windows, looks for 4 or more failures across 3 or more different users
- Reports exact list of targeted usernames for investigation

**Real-world scenario:** Attacker from IP 5.5.5.5 tries "Password123" against users: user10, user19, user2, user20 within 10 minutes. Each user only sees 1 failed attempt (below lockout threshold), but collectively it's clear attack pattern.

**Why parameters:** 3+ users shows targeting breadth, 4+ attempts shows persistence, 15-minute window captures typical spray campaigns.

```python
# Configuration in analyze.py
SPRAY_MIN_USERS = 3     # Minimum users targeted
SPRAY_MIN_FAILS = 4     # Minimum total failures
SPRAY_WINDOW_MIN = 15   # Detection window (minutes)
```

### 5. ML Behavioral Anomaly Detection (LOF)
**What it detects:** Unknown attack patterns and behavioral anomalies that don't fit predefined rules

**Why machine learning approach:**  
Security threats constantly evolve. Rule-based systems only catch known patterns. ML detects statistical outliers in user behavior, catching "zero-day" attack methods we haven't seen before.

**Algorithm choice - Local Outlier Factor (LOF):**  
- **Unsupervised learning** (no labeled training data needed)
- **Local density analysis** (compares each event to its k-nearest neighbors)  
- **Explainable results** (can identify which features made something anomalous)
- **Robust to imbalanced data** (works well with rare anomalies)

**Feature engineering (10 behavioral dimensions):**  
```python
features = [
    'is_private',          # Network context: internal vs external
    'is_success',          # Action outcome
    'is_fail',             # Action outcome  
    'is_download',         # Action type
    'is_change',           # Action type
    'hour',                # Temporal context
    'fail_count_win',      # Sliding window: failure density
    'success_count_win',   # Sliding window: success density
    'unique_ips_win',      # Sliding window: IP diversity
    'delta_min_from_prev'  # Time gap between actions
]
```

**Detection logic:**  
- Builds 30-minute sliding windows for each user's activity
- Calculates behavioral features for each event
- Applies LOF algorithm to identify outliers (contamination=1%)
- Provides human-readable explanations for each anomaly

**Real-world scenarios ML catches:**  
- User suddenly downloads multiple files at unusual hours
- Account shows rapid-fire activity from multiple IPs (possible bot behavior)  
- User performs actions they've never done before during off-hours

**Explainable AI example:**  
```
"LOF flagged (fails_win=0, unique_ips_win=1, is_private=0, hour=14)"
Translation: Unusual pattern detected based on failure counts, IP usage, network type, and time
```

**Configuration:**
```python
# ML Configuration in analyze.py
ML_CONTAMINATION = 0.01     # Expected anomaly rate (1%)
ML_WINDOW_MIN = 30          # Feature analysis window (minutes)
```

---

## Output Format

### JSON Results (`outputs/anomalies.json`)
```json
[
  {
    "type": "bruteforce",
    "timestamp": "2025-09-04 10:00:00",
    "user_id": "user14",
    "ip_address": "203.0.113.200",
    "reason": "Possible brute-force: 8 failed logins in 10 minutes",
    "mitigation": "block_ip"
  },
  {
    "type": "suspicious_ip",
    "timestamp": "2025-09-01 12:13:00",
    "user_id": "user16",
    "ip_address": "151.101.1.69",
    "reason": "First-seen public IP for user (>60d gap) & recent failures from same IP (≤60m)",
    "mitigation": "alert_admin"
  },
  {
    "type": "geo_hop",
    "timestamp": "2025-09-06 09:04:00",
    "user_id": "user16",
    "ip_address": "3.5.140.16",
    "reason": "Geo-hop detected: DE → KR within 0 days 00:04:00",
    "mitigation": "alert_admin"
  },
  {
    "type": "password_spraying",
    "timestamp": "2025-09-03 14:01:43",
    "user_id": ["user10", "user19", "user2", "user20"],
    "ip_address": "5.5.5.5",
    "reason": "Password spraying: 4 failed logins on 4 users (user10,user19,user2,user20) within 15 minutes",
    "mitigation": "block_ip"
  },
  {
    "type": "ml_anomaly",
    "timestamp": "2025-09-03 14:03:21",
    "user_id": "user11",
    "ip_address": "5.5.5.5",
    "ml_score": 0.6464,
    "reason": "LOF flagged (fails_win=0, unique_ips_win=1, is_private=0, hour=14)",
    "mitigation": "review"
  }
]
```

### Professional Visualization
**File:** `outputs/anomaly_analysis.png`  
**Content:** Hourly threat activity chart with:
- Temporal threat patterns throughout the day
- Business hours context (8 AM - 6 PM highlighted) 
- Key statistics and peak activity analysis

---

## Dependencies

**Core Requirements (`requirements.txt`):**
```
pandas>=1.5.0
numpy>=1.21.0
scikit-learn>=1.1.0
matplotlib>=3.5.0
geoip2>=4.6.0
```

---

## Troubleshooting

**GeoIP Database Missing:**
```
Error: [Errno 2] No such file or directory: 'geoip/GeoLite2-Country.mmdb'
```
**Solution:** Download and place GeoIP database as described in Step 2

**Module Import Errors:**
```
ModuleNotFoundError: No module named 'sklearn'
```
**Solution:** Activate virtual environment and install requirements:
```bash
venv\Scripts\activate
pip install -r requirements.txt
```

---

### Bonus Features Implemented:
**Visualizations:** Professional hourly threat activity chart  
**Suggested mitigations:** Block IP, alert admin, review recommendations  
**ML-based methods:** Local Outlier Factor with explainable AI

---

## Technical Highlights

- **Efficient algorithms:** sliding window for brute-force detection
- **Smart filtering:** Reduces false positives with dual-condition logic
- **Explainable ML:** Human-readable explanations for ML anomalies
- **Production-ready:** Comprehensive error handling and logging
- **Configurable:** All parameters adjustable for different environments

---

