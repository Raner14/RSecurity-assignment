from pathlib import Path
import pandas as pd
import ipaddress
import json
from datetime import timedelta
import geoip2.database


# ---------- Config ----------
BRUTEFORCE_WINDOW_MIN = 10
BRUTEFORCE_THRESHOLD = 5

GEOHOP_WINDOW_MIN = 5

SPRAY_WINDOW_MIN = 15     # חלון זמן בדקות
SPRAY_MIN_USERS = 3      # לפחות X משתמשים שונים
SPRAY_MIN_FAILS = 4      # לפחות Y כשלונות
# ----------------------------


# File paths
DATA = Path(__file__).resolve().parents[1] / "data" / "sample_logs_no_status.csv"
GEOIP_DB = Path(__file__).resolve().parents[1] / "geoip" / "GeoLite2-Country.mmdb"
OUT = Path(__file__).resolve().parents[1] / "outputs" / "anomalies.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


def load_logs():
    """
    Load the raw CSV logs into a DataFrame.

    Returns:
        pd.DataFrame: Parsed log data with datetime(library).
    """
    df = pd.read_csv(DATA)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def detect_bruteforce(df):
    """
    Detect brute-force attempts:
    Many login_failed events from the same IP within a short time window.

    Args:
        df (pd.DataFrame): Log dataset.

    Returns:
        list[dict]: List of anomalies.
    """
    anomalies = []

    fails = df[df["action"] == "login_failed"].copy()  # filter only "login_failed"

    for ip, group in fails.groupby("ip_address"):   # group by IP
        group = group.sort_values("timestamp").reset_index(drop=True)


        for i in range(len(group)):
            start_time = group.loc[i, "timestamp"]
            window = group[
                (group["timestamp"] >= start_time) &
                (group["timestamp"] <= start_time + timedelta(minutes=BRUTEFORCE_WINDOW_MIN))
                ]

            if len(window) >= BRUTEFORCE_THRESHOLD:   # threshold check
                anomalies.append({
                    "type": "bruteforce",
                    "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": group.loc[i, "user_id"],
                    "ip_address": ip,
                    "reason": f"Possible brute-force: {len(window)} failed logins in {BRUTEFORCE_WINDOW_MIN} minutes"
                })
                break  # avoid duplicates

    return anomalies


def detect_suspicious_ips(df):
    """
    Detect suspicious logins from public IPs:
    login_success events coming from non-private IP ranges.

    Args:
        df (pd.DataFrame): Log dataset.

    Returns:
        list[dict]: List of anomalies.
    """
    anomalies = []

    login_successes = df[df["action"] == "login_success"].copy()  # filter only "login_success"

    def is_public_ip(ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_private  # check private vs public
        except ValueError:
            return False

    login_successes["is_public"] = login_successes["ip_address"].apply(is_public_ip)

    suspicious = login_successes[login_successes["is_public"]]   # keep only public IPs

    for _, row in suspicious.iterrows():
        anomalies.append({
            "type": "suspicious_ip",
            "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": row["user_id"],
            "ip_address": row["ip_address"],
            "reason": "Suspicious IP: login_success from public IP address"
        })

    return anomalies


def detect_geo_hops(df, geoip_db_path: str | Path = GEOIP_DB):
    """
    Detect geo-hops:
    Same user logs in from different countries within a short time window.

    Args:
        df (pd.DataFrame): Log dataset.
        geoip_db_path (str|Path): Path to GeoLite2 DB.

    Returns:
        list[dict]: List of anomalies.
    """
    anomalies = []
    geoip_db_path = Path(geoip_db_path)
    if not geoip_db_path.exists():
        raise FileNotFoundError(f"GeoIP DB not found at: {geoip_db_path}")

    successes = df[df["action"] == "login_success"].copy()   # only successful logins
    reader = geoip2.database.Reader(str(geoip_db_path))

    try:
        def ip_to_country(ip: str) -> str:
            try:
                code = reader.country(ip).country.iso_code
                return code if code else "UNKNOWN"
            except Exception:
                return "UNKNOWN"

        successes["country"] = successes["ip_address"].apply(ip_to_country)

        for user, group in successes.groupby("user_id"):  # group by "user_id"
            group = group.sort_values("timestamp").reset_index(drop=True)

            for i in range(1, len(group)):
                prev = group.loc[i - 1]
                curr = group.loc[i]
                time_diff = curr["timestamp"] - prev["timestamp"]

                if prev["country"] != curr["country"] and time_diff <= timedelta(minutes=GEOHOP_WINDOW_MIN):
                    anomalies.append({
                        "type": "geo_hop",
                        "timestamp": curr["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        "user_id": user,
                        "ip_address": curr["ip_address"],
                        "reason": f"Geo-hop detected: {prev['country']} → {curr['country']} within {time_diff}"
                    })
    finally:
        reader.close()

    return anomalies


def detect_password_spraying(df,
                             window_min: int = SPRAY_WINDOW_MIN,
                             min_users: int = SPRAY_MIN_USERS,
                             min_fails: int = SPRAY_MIN_FAILS):
    """
      Detect password spraying:
      Many login_failed events from the same IP targeting multiple users in a short window.

      Args:
          df (pd.DataFrame): Log dataset.
          window_min (int): Time window in minutes.
          min_users (int): Minimum distinct users.
          min_fails (int): Minimum number of failures.

      Returns:
          list[dict]: List of anomalies.
      """
    anomalies = []
    fails = df[df["action"] == "login_failed"].copy()    # filter only "login_failed"
    if fails.empty:
        return anomalies

    for ip, group in fails.groupby("ip_address"):   # group by "ip_address"
        group = group.sort_values("timestamp").reset_index(drop=True)

        left = 0
        for right in range(len(group)):
            while group.loc[right, "timestamp"] - group.loc[left, "timestamp"] > timedelta(minutes=window_min):
                left += 1

            window = group.iloc[left:right+1]
            unique_users = window["user_id"].nunique()
            total_fails = len(window)

            if unique_users >= min_users and total_fails >= min_fails:
                anomalies.append({
                    "type": "password_spraying",
                    "timestamp": window.iloc[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": "*multiple*",
                    "ip_address": ip,
                    "reason": (f"Password spraying: {total_fails} failed logins "
                               f"on {unique_users} users within {window_min} minutes")
                })
                break
    return anomalies


def main():
    """
    1. Load log data from CSV
    2. Run all anomaly detectors
    3. Merge results into a single list
    4. Save anomalies into a JSON report
    5. Print a short summary to console
    """

    df = load_logs()  #Load logs into DataFrame

    anomalies = []   #list to collect anomalies
    anomalies.extend(detect_bruteforce(df))
    anomalies.extend(detect_suspicious_ips(df))
    anomalies.extend(detect_geo_hops(df, GEOIP_DB))
    anomalies.extend(detect_password_spraying(df))

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(anomalies, f, indent=2, ensure_ascii=False)

    print(f"✅ Found {len(anomalies)} anomalies. Saved to {OUT}")


if __name__ == "__main__":
    main()
