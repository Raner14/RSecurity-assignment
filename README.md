RSecurity Internship Assignment - Sample Log (no status column)
---------------------------------------------------------------

# Security/Analysis – Detect Suspicious Activity


This project analyzes raw activity logs (`CSV`) and detects suspicious behaviors that may indicate security incidents.

---

## 📂 Project Structure
```
rsecurity-assignment/
│── data/
│   └── sample_logs_no_status.csv    # Input log file
│── geoip/
│   └── GeoLite2-Country.mmdb        # GeoIP database (local only, not uploaded)
│── outputs/
│   └── anomalies.json               # Detected anomalies are saved here
│── src/
│   └── analyze.py                   # Main analysis script
│── README.md
│── requirements.txt
│── .gitignore
```

---

## ⚙️ How to Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
    > Make sure `scikit-learn` and `numpy` are included.

2. Place the **GeoLite2-Country.mmdb** file in the `geoip/` directory.  
   (Download instructions below).
3. Run the main script:
   ```bash
   python src/analyze.py
   ```
4. Results will be saved in:
   ```
   outputs/anomalies.json
   ```

---

## Download GeoLite2 Database

This project requires the **MaxMind GeoLite2-Country** database to resolve IP addresses to countries.
Because of MaxMind’s licensing, the database file **cannot be included** directly in this repository.

### Steps to download:

1. Create a free account at [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Log in and navigate to the **GeoLite2-Country** section.
3. Download the **Binary (.mmdb) format** of the database.
4. Place the downloaded file inside the `geoip/` directory of this project:

   ```
   geoip/GeoLite2-Country.mmdb
   ```

⚠️⚠️⚠️ Without this file, the **Geo-hop detection** feature will not work.

---

## Detection Methods

The system detects multiple types of anomalies, each covering a different **attack pattern** seen in real-world scenarios.

### 1. Brute-force Detection
- **What it is:**  
  Many failed logins (`login_failed`) from the **same IP** against the **same user** in a short time.  
- **Why important:**  
  Classic attack where the attacker guesses the password of one target account.  
- **How we detect:**  
  - Group events by `ip_address`.  
  - Check sliding windows of 10 minutes.  
  - If ≥5 failures for the same user → flagged.

---

### 2. Suspicious IPs 
- **What it is:**  
  Successful logins (`login_success`) from **new public IP addresses** that the user has not used recently, **combined with recent failed attempts from the same IP**.  
- **Why important:**  
  This reduces false positives (e.g., normal remote workers, VPNs, mobile networks) and highlights cases more likely to indicate compromise:
  - A **new external IP** suddenly used by the account.  
  - That IP already had **failed login attempts** before the success.  
- **How we detect:**  
  - Check if `ip_address` is **public**.  
  - Flag only if:  
    1. The IP has **not been seen for the user in the last 60 days**, **and**  
    2. There were **failed logins from the same IP within the last 60 minutes**.  
  - Each `(user, ip)` combination is reported **once per day** to avoid duplicates.  

---

### 3. Geo-hops
- **What it is:**  
  The same user logs in from **two different countries** within a short time (≤5 minutes).  
- **Why important:**  
  Physically impossible behavior, usually means account compromise.  
- **How we detect:**  
  - Resolve IP → country using `geoip2`.  
  - Group by `user_id`, sort by `timestamp`.  
  - If country changes within 5 minutes → flagged.

---


### 4. Password Spraying
- **What it is:**  
  Attacker tries **one/few passwords** across **many users**, instead of targeting a single account.  
- **Why important:**  
  This method avoids account lockouts and is harder to spot than brute-force.  
- **How we detect:**  
  - Group by `ip_address`.  
  - Within 15 minutes, if there are ≥4 failed logins across ≥3 different users → flagged.
  - The output includes the exact list of targeted users.

---

### 5. Bonus – ML Anomaly Detection (LOF)
- **What it is:**  
  An unsupervised ML detector using **Local Outlier Factor (LOF)** from `scikit-learn`.  
- **Why important:**  
  Detects unusual behavior that does not fit predefined rules, catching “unknown unknowns”.  
- **How we detect:**  
  - Build behavioral features for each event:  
    - Action flags (`is_success`, `is_fail`, `is_download`, `is_change`)  
    - Context (`hour`, `delta_min_from_prev`)  
    - Network (`is_private`, `unique_ips_win`)  
    - Sliding window counts (`fail_count_win`, `success_count_win`)  
  - Run LOF with `contamination=0.01` (~1% anomalies).  
  - Events with low local density are flagged as `ml_anomaly`.  

- **Configurable parameters (see `analyze.py`):**  
  - `ML_ENABLE` → enable/disable ML detection (default: True).  
  - `ML_WINDOW_MIN` → sliding window size for features (default: 30 minutes).  
  - `ML_CONTAMINATION` → expected anomaly fraction (default: 0.01).  
  - `n_neighbors` in LOF (default: 20).  


⚠️ **Note:** ML anomalies should not trigger automatic blocking. They are an **early-warning signal** for analysts and should be combined with rule-based detections.

---





## 📑 Example Output (JSON)

```json
[
{
    "type": "bruteforce",
    "timestamp": "2025-09-04 10:00:00",
    "user_id": "user14",
    "ip_address": "203.0.113.200",
    "reason": "Possible brute-force: 8 failed logins in 10 minutes"
  },
  {
    "type": "suspicious_ip",
    "timestamp": "2025-09-01 12:13:00",
    "user_id": "user16",
    "ip_address": "151.101.1.69",
    "reason": "First-seen public IP for user (>60d gap) & recent failures from same IP (≤60m)"
  },
  {
    "type": "geo_hop",
    "timestamp": "2025-09-06 09:04:00",
    "user_id": "user16",
    "ip_address": "3.5.140.16",
    "reason": "Geo-hop detected: DE → KR within 0 days 00:04:00"
  },
  {
    "type": "password_spraying",
    "timestamp": "2025-09-03 14:01:43",
    "user_id": [
      "user10",
      "user19",
      "user2",
      "user20"
    ],
    "ip_address": "5.5.5.5",
    "reason": "Password spraying: 4 failed logins on 4 users (user10,user19,user2,user20) within 15 minutes"
  },
  {
    "type": "ml_anomaly",
    "timestamp": "2025-09-03 14:03:21",
    "user_id": "user11",
    "ip_address": "5.5.5.5",
    "ml_score": 0.6464,
    "reason": "LOF flagged (fails_win=0, unique_ips_win=1, is_private=0, hour=14)"
  }
]
```

---

  


