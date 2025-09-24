from pathlib import Path
from datetime import timedelta
import ipaddress
import json
import pandas as pd
import geoip2.database
import numpy as np
from sklearn.neighbors import LocalOutlierFactor


# ============================================================
#                       Config Parameters
# ============================================================

# ---- Machine Learning (LOF) ----
ML_ENABLE = True           # Enable/disable ML anomaly detection
ML_WINDOW_MIN = 30         # Time window (in minutes) for feature calculation
ML_CONTAMINATION = 0.01    # Expected fraction of anomalies in the dataset

# ---- Brute-force Detection ----
BRUTEFORCE_WINDOW_MIN = 10  # Time window (minutes) to check repeated login failures
BRUTEFORCE_THRESHOLD = 5    # Number of failed logins within the window to trigger alert

# ---- Geo-hop Detection ----
GEOHOP_WINDOW_MIN = 5      # Max time (minutes) between two logins from different countries

# ---- Password Spraying ----
SPRAY_WINDOW_MIN = 15     # Time window (minutes) to analyze failed logins
SPRAY_MIN_USERS = 3       # Minimum distinct users targeted from the same IP
SPRAY_MIN_FAILS = 4       # Minimum failed attempts in the time window

# ---- Suspicious IP Detection ----
SUSPICIOUS_FIRST_SEEN_DAYS = 60    # Days after which a public IP is considered "new" for a user
SUSPICIOUS_FAIL_LOOKBACK_MIN = 60  # Minutes to check for failed logins before a suspicious success
# ============================================================


# ============================================================
#                         Paths
# ============================================================
DATA = Path(__file__).resolve().parents[1] / "data" / "sample_logs_no_status.csv"
GEOIP_DB = Path(__file__).resolve().parents[1] / "geoip" / "GeoLite2-Country.mmdb"
OUT = Path(__file__).resolve().parents[1] / "outputs" / "anomalies.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
#                      Data Loading
# ============================================================
def load_logs():
    """
    Load the raw CSV logs into a DataFrame.

    Returns:
        pd.DataFrame: Parsed log data with datetime(library).
    """
    df = pd.read_csv(DATA)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def detect_bruteforce(df: pd.DataFrame) -> list[dict]:
    """
    Simple and efficient brute-force detection using a sliding-window (two pointers).

    Logic:
      - Group events by (ip_address, user_id) so we detect repeated failed attempts
        from the same IP against the same user.
      - For each group, use two-pointer sliding window over timestamps to count failures
        inside BRUTEFORCE_WINDOW_MIN. If count >= BRUTEFORCE_THRESHOLD -> flag once.

    Returns:
      list[dict] anomalies in the same shape as the rest of the code expects.
    """
    anomalies: list[dict] = []

    # keep only failed logins (we're detecting repeated failures)
    fails = df[df["action"] == "login_failed"].copy()
    if fails.empty:
        return anomalies

    # group by both IP and user to ensure "same IP against same user"
    for (ip, user), group in fails.groupby(["ip_address", "user_id"]):
        group = group.sort_values("timestamp").reset_index(drop=True)
        left = 0

        # sliding window: expand right, move left while window too large
        for right in range(len(group)):
            # move left pointer until window fits within BRUTEFORCE_WINDOW_MIN
            while group.loc[right, "timestamp"] - group.loc[left, "timestamp"] > timedelta(minutes=BRUTEFORCE_WINDOW_MIN):
                left += 1

            window_size = right - left + 1
            if window_size >= BRUTEFORCE_THRESHOLD:
                start_time = group.loc[left, "timestamp"]
                anomalies.append({
                    "type": "bruteforce",
                    "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": user,
                    "ip_address": ip,
                    "reason": f"Possible brute-force: {window_size} failed logins in {BRUTEFORCE_WINDOW_MIN} minutes"
                })
                break  # report this (ip,user) once and move to next group

    return anomalies



def detect_suspicious_ips(df: pd.DataFrame) -> list[dict]:
    """
    Detect suspicious login_success events from public IPs.
    A login is flagged only if BOTH conditions hold:
      1) The public IP is first-seen for the user within the last SUSPICIOUS_FIRST_SEEN_DAYS days.
      2) There were login_failed events from the same IP within the last SUSPICIOUS_FAIL_LOOKBACK_MIN minutes.
    Daily de-duplication is applied per (user, ip).
    """
    anomalies = []
    if df.empty:
        return anomalies

    d = df.copy().sort_values("timestamp").reset_index(drop=True)
    succ = d[d["action"] == "login_success"]
    fails = d[d["action"] == "login_failed"]

    def _is_public_ip(ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    last_seen = {}             # (user, ip) -> last timestamp
    reported_today = set()     # {(yyyy-mm-dd, user, ip)}

    cutoff_days = timedelta(days=SUSPICIOUS_FIRST_SEEN_DAYS)

    for _, row in succ.iterrows():
        user = row["user_id"]
        ip = row["ip_address"]
        ts = row["timestamp"]

        # Only public IPs
        if not _is_public_ip(ip):
            last_seen[(user, ip)] = ts
            continue

        # First-seen logic (per user, per IP)
        prev_ts = last_seen.get((user, ip))
        is_first_seen = (prev_ts is None) or ((ts - prev_ts) > cutoff_days)
        last_seen[(user, ip)] = ts
        if not is_first_seen:
            continue

        # Check for recent fails within the lookback window
        start = ts - timedelta(minutes=SUSPICIOUS_FAIL_LOOKBACK_MIN)
        recent_fails = fails[
            (fails["ip_address"] == ip) &
            (fails["timestamp"] >= start) &
            (fails["timestamp"] < ts)
        ]
        if recent_fails.empty:
            continue

        # Daily de-duplication
        day_key = (ts.strftime("%Y-%m-%d"), user, ip)
        if day_key in reported_today:
            continue
        reported_today.add(day_key)

        anomalies.append({
            "type": "suspicious_ip",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": user,
            "ip_address": ip,
            "reason": (
                f"First-seen public IP for user (>{SUSPICIOUS_FIRST_SEEN_DAYS}d gap) "
                f"& recent failures from same IP (≤{SUSPICIOUS_FAIL_LOOKBACK_MIN}m)"
            ),
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
                users_in_window = sorted(window["user_id"].unique().tolist())

                anomalies.append({
                    "type": "password_spraying",
                    "timestamp": window.iloc[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": users_in_window,
                    "ip_address": ip,
                    "reason": (f"Password spraying: {total_fails} failed logins on {unique_users} users "
                               f"({','.join(users_in_window)}) within {window_min} minutes")
                })
                break
    return anomalies

def _is_private_ip(ip: str) -> int:
    """1 אם IP פרטי, אחרת 0 (עם טיפול בשגיאות)."""
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0

def _build_simple_features(df: pd.DataFrame, window_min: int = ML_WINDOW_MIN) -> pd.DataFrame:
    """
    בונה פיצ'רים *פשוטים וברורים* לכל אירוע:
    - דגלי פעולה (success/fail/download/change)
    - שעה ביממה
    - האם ה-IP פרטי
    - ספירת כשלונות/הצלחות למשתמש בחלון זמן
    - מספר IP-ים ייחודיים למשתמש בחלון זמן
    - דקות מאז האירוע הקודם של אותו משתמש
    """
    df = df.copy().sort_values("timestamp").reset_index(drop=True)

    # דגלי פעולה בסיסיים
    df["is_success"]  = (df["action"] == "login_success").astype(int)
    df["is_fail"]     = (df["action"] == "login_failed").astype(int)
    df["is_download"] = (df["action"] == "download_file").astype(int)
    df["is_change"]   = (df["action"] == "change_settings").astype(int)
    df["hour"]        = df["timestamp"].dt.hour
    df["is_private"]  = df["ip_address"].apply(_is_private_ip)

    parts = []
    w = window_min

    # נחשב פיצ'רים “בהקשר משתמש”
    for _, g in df.groupby("user_id", group_keys=False):
        g = g.sort_values("timestamp").reset_index(drop=True).copy()

        # סכומי rolling לפי זמן (pandas יודע לחשב לפי טיימסטמפ)
        g["fail_count_win"]    = g[["timestamp","is_fail"]].rolling(f"{w}min", on="timestamp").sum().fillna(0)["is_fail"]
        g["success_count_win"] = g[["timestamp","is_success"]].rolling(f"{w}min", on="timestamp").sum().fillna(0)["is_success"]

        # unique IPs בחלון זמן — two-pointers (מדויק למחרוזות)
        uniq = []
        left = 0
        from datetime import timedelta as _td
        for right in range(len(g)):
            tr = g.loc[right, "timestamp"]
            while tr - g.loc[left, "timestamp"] > _td(minutes=w):
                left += 1
            uniq.append(g.loc[left:right, "ip_address"].nunique())
        g["unique_ips_win"] = uniq

        # דקות מאז האירוע הקודם של אותו משתמש
        g["delta_min_from_prev"] = g["timestamp"].diff().dt.total_seconds().div(60).fillna(9999)

        parts.append(g)

    feat = pd.concat(parts, ignore_index=True)

    # עמודות הפיצ'רים שנזין למודל
    feature_cols = [
        "is_private","is_success","is_fail","is_download","is_change","hour",
        "fail_count_win","success_count_win","unique_ips_win","delta_min_from_prev"
    ]
    X = feat[feature_cols].astype(float).replace([np.inf, -np.inf], 0).fillna(0).values
    feat["_ml_vector"] = list(X)   # נשמור את הווקטור לכל שורה
    return feat

def detect_ml_lof(df: pd.DataFrame,
                  contamination: float = ML_CONTAMINATION,
                  window_min: int = ML_WINDOW_MIN) -> list[dict]:
    """
    ML פשוט: Local Outlier Factor (LOF).
    הרעיון: אירוע שמצפיפותו המקומית נמוכה בהרבה משל שכניו → חריג.

    החזרה: רשימת אנומליות במבנה זהה לדיטקטורים שלך.
    """
    anomalies = []
    feat = _build_simple_features(df, window_min=window_min)
    X = np.vstack(feat["_ml_vector"].values)

    # LOF: מחזיר -1 לחריגים, 1 לנורמליים. ככל שה-factor נמוך יותר → חריג יותר.
    lof = LocalOutlierFactor(n_neighbors=20, contamination=contamination, novelty=False, n_jobs=-1)
    y_pred = lof.fit_predict(X)                        # -1 = חריג
    scores = -lof.negative_outlier_factor_            # גבוה = חריג
    # נרמול 0..1 לנוחות קריאה
    scores_norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

    feat["ml_score"] = scores_norm
    feat["ml_flag"] = (y_pred == -1).astype(int)

    flagged = feat[feat["ml_flag"] == 1].copy().reset_index(drop=True)

    for _, r in flagged.iterrows():
        # הסבר קצר וברור “למה סומן” על בסיס הפיצ'רים
        reason = (
            f"LOF flagged (fails_win={int(r['fail_count_win'])}, "
            f"unique_ips_win={int(r['unique_ips_win'])}, "
            f"is_private={int(r['is_private'])}, hour={int(r['hour'])})"
        )
        anomalies.append({
            "type": "ml_anomaly",
            "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": r["user_id"],
            "ip_address": r["ip_address"],
            "ml_score": float(round(r["ml_score"], 4)),
            "reason": reason
            # (את ה-mitigations תוסיף אחר כך – לפי הבונוס הבא)
        })

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
    # ---- BONUS: ML (LOF) ----
    if ML_ENABLE:
        anomalies.extend(detect_ml_lof(df, contamination=ML_CONTAMINATION, window_min=ML_WINDOW_MIN))


    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(anomalies, f, indent=2, ensure_ascii=False)

    print(f"✅ Found {len(anomalies)} anomalies. Saved to {OUT}")


if __name__ == "__main__":
    main()
