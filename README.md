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
2. Place the **GeoLite2-Country.mmdb** file in the `geoip/` directory.  
   (Instructions to download are in line 47-63).
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
  Successful logins (`login_success`) from **public IPs** instead of internal office ranges (e.g., `192.168.x.x`, `10.x.x.x`).  
- **Why important:**  
  Normal employees are expected to connect from internal/private networks.  
- **How we detect:**  
  - Convert each `ip_address` to `private/public`.  
  - If login comes from a **public IP** → flagged.

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

---

## 📑 Example Output (JSON)

```json
[
  {
    "type": "geo_hop",
    "timestamp": "2025-09-01 08:22:00",
    "user_id": "user2",
    "ip_address": "92.123.45.13",
    "reason": "Geo-hop detected: IL → US within 0:05:00"
  },
  {
    "type": "password_spraying",
    "timestamp": "2025-09-01 09:10:00",
    "user_id": "*multiple*",
    "ip_address": "203.0.113.55",
    "reason": "Password spraying: 6 failed logins on 4 users within 15 minutes"
  }
]
```

  

