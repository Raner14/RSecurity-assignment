from pathlib import Path
from datetime import timedelta
import ipaddress
import json
import pandas as pd
import geoip2.database
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
import matplotlib.pyplot as plt

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
                    "reason": f"Possible brute-force: {window_size} failed logins in {BRUTEFORCE_WINDOW_MIN} minutes",
                    "mitigation": "block_ip"
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
            "mitigation": "alert_admin"
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
                        "reason": f"Geo-hop detected: {prev['country']} → {curr['country']} within {time_diff}",
                        "mitigation": "alert_admin"
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
                               f"({','.join(users_in_window)}) within {window_min} minutes"),
                    "mitigation": "block_ip"
                })
                break
    return anomalies


def _is_private_ip(ip: str) -> int:
    """
    Check if IP address is private

    Args:
        ip (str): IP address to classify

    Returns:
        int: 1 if private IP, 0 if public/invalid
    """
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0  # Treat invalid IPs as public (conservative)


def _build_simple_features(df: pd.DataFrame, window_min: int = ML_WINDOW_MIN) -> pd.DataFrame:
    """
    Build behavioral features for ML anomaly detection.

    Creates 10 features per event: action flags, temporal patterns,
    network info, and user context within sliding time windows.

    Args:
        df (pd.DataFrame): Log data with timestamp, user_id, action, ip_address
        window_min (int): Time window for rolling calculations (default: 30)

    Returns:
        pd.DataFrame: Enhanced data with feature columns and _ml_vector

    Raises:
        ValueError: If required columns missing or invalid parameters
    """
    # Input validation
    if df.empty:
        return df.copy()

    required_cols = ['timestamp', 'user_id', 'action', 'ip_address']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")

    if window_min <= 0:
        raise ValueError(f"window_min must be positive, got {window_min}")

    # Prepare data
    df = df.copy().sort_values("timestamp").reset_index(drop=True)

    # Basic action type features
    df["is_success"] = (df["action"] == "login_success").astype(int)
    df["is_fail"] = (df["action"] == "login_failed").astype(int)
    df["is_download"] = (df["action"] == "download_file").astype(int)
    df["is_change"] = (df["action"] == "change_settings").astype(int)
    df["hour"] = df["timestamp"].dt.hour
    df["is_private"] = df["ip_address"].apply(_is_private_ip)

    parts = []
    w = window_min

    # Calculate per-user contextual features
    for user_id, g in df.groupby("user_id", group_keys=False):
        try:
            g = g.sort_values("timestamp").reset_index(drop=True).copy()

            # Rolling window aggregations using pandas time-aware rolling
            g["fail_count_win"] = g[["timestamp", "is_fail"]].rolling(f"{w}min", on="timestamp").sum().fillna(0)[
                "is_fail"]
            g["success_count_win"] = g[["timestamp", "is_success"]].rolling(f"{w}min", on="timestamp").sum().fillna(0)[
                "is_success"]

            # Unique IP count using two-pointer sliding window (more accurate for strings)
            uniq = []
            left = 0
            for right in range(len(g)):
                current_time = g.loc[right, "timestamp"]
                # Shrink window from left to maintain time constraint
                while current_time - g.loc[left, "timestamp"] > timedelta(minutes=w):
                    left += 1
                # Count unique IPs in current window [left:right]
                uniq.append(g.loc[left:right, "ip_address"].nunique())
            g["unique_ips_win"] = uniq

            # Time since previous activity for same user
            g["delta_min_from_prev"] = (
                g["timestamp"]
                .diff()
                .dt.total_seconds()
                .div(60)
                .fillna(9999)  # Large value for first activity
            )

            parts.append(g)

        except Exception as e:
            print(f"Warning: Failed to process user {user_id}: {str(e)}")
            continue

    # Combine all user features
    feat = pd.concat(parts, ignore_index=True) if parts else df.copy()

    # Create feature matrix for ML
    feature_cols = [
        "is_private", "is_success", "is_fail", "is_download", "is_change", "hour",
        "fail_count_win", "success_count_win", "unique_ips_win", "delta_min_from_prev"
    ]

    # Validate feature columns exist
    missing_features = [col for col in feature_cols if col not in feat.columns]
    if missing_features:
        raise RuntimeError(f"Missing feature columns: {missing_features}")

    # Build feature matrix with proper error handling
    X = feat[feature_cols].astype(float).replace([np.inf, -np.inf], 0).fillna(0).values
    feat["_ml_vector"] = list(X)

    return feat


def detect_ml_lof(df: pd.DataFrame,
                  contamination: float = ML_CONTAMINATION,
                  window_min: int = ML_WINDOW_MIN) -> list[dict]:
    """
    Detect behavioral anomalies using Local Outlier Factor (LOF).

    Identifies events with unusual behavioral patterns by comparing
    local density with neighbors. Effective for unknown attack types.

    Args:
        df (pd.DataFrame): Log data with timestamp, user_id, action, ip_address
        contamination (float): Expected anomaly fraction (0.0-0.5, default: 0.01)
        window_min (int): Time window for features in minutes (default: 30)

    Returns:
        list[dict]: Anomalies with type, timestamp, user_id, ip_address,
                   ml_score, reason, mitigation

    Raises:
        ValueError: If contamination out of range or insufficient data
        RuntimeError: If ML processing fails
    """
    # Input validation
    if not 0.0 <= contamination <= 0.5:
        raise ValueError(f"Contamination must be between 0.0 and 0.5, got {contamination}")

    if df.empty:
        return []

    anomalies = []

    try:
        # Build behavioral features
        feat = _build_simple_features(df, window_min=window_min)
        X = np.vstack(feat["_ml_vector"].values)

        # Prevent n_neighbors > sample size (critical fix)
        n_neighbors = min(20, len(X) - 1) if len(X) > 1 else 1

        if n_neighbors < 1:
            print("Warning: Not enough samples for LOF analysis")
            return []

        # Apply LOF algorithm
        lof = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=contamination,
            novelty=False,
            n_jobs=-1
        )

        y_pred = lof.fit_predict(X)  # -1 = anomaly, 1 = normal
        scores = -lof.negative_outlier_factor_  # Higher = more anomalous

        # Normalize scores to 0-1 range for interpretability
        scores_norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

        # Add ML results to feature data
        feat["ml_score"] = scores_norm
        feat["ml_flag"] = (y_pred == -1).astype(int)

        # Extract flagged anomalies
        flagged = feat[feat["ml_flag"] == 1].copy().reset_index(drop=True)

        # Convert to standardized anomaly format
        for _, event in flagged.iterrows():
            reason = _generate_ml_explanation(event)

            anomalies.append({
                "type": "ml_anomaly",
                "timestamp": event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": event["user_id"],
                "ip_address": event["ip_address"],
                "ml_score": float(round(event["ml_score"], 4)),
                "reason": reason,
                "mitigation": "review"
            })

    except Exception as e:
        raise RuntimeError(f"ML anomaly detection failed: {str(e)}")

    return anomalies


def _generate_ml_explanation(event: pd.Series) -> str:
    """Generate human-readable explanation for ML anomaly."""
    indicators = []

    if event["fail_count_win"] > 2:
        indicators.append(f"high_failures({int(event['fail_count_win'])})")

    if event["unique_ips_win"] > 1:
        indicators.append(f"multiple_ips({int(event['unique_ips_win'])})")

    if event["is_private"] == 0:
        indicators.append("public_ip")

    if event["hour"] < 6 or event["hour"] > 22:
        indicators.append(f"unusual_hour({int(event['hour'])})")

    if event.get("delta_min_from_prev", 0) < 1:
        indicators.append("rapid_succession")

    key_factors = ", ".join(indicators) if indicators else "behavioral_pattern"
    return f"LOF detected anomaly: {key_factors}"


def plot_advanced_analytics(anomalies):
    """
    Single professional visualization: Hourly threat activity with detection insights.
    """


    if not anomalies:
        print("⚠️  No anomalies to visualize")
        return

    # Prepare data
    df = pd.DataFrame(anomalies)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour

    # Create single visualization
    plt.figure(figsize=(12, 6))

    # Hourly distribution with professional styling
    hourly_data = df['hour'].value_counts().sort_index()
    bars = plt.bar(hourly_data.index, hourly_data.values,
                   color='#E74C3C', alpha=0.8, edgecolor='black')

    # Enhance visualization
    plt.title(' Security Threats - Hourly Activity Pattern',
              fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Hour of Day', fontsize=11)
    plt.ylabel('Number of Threats', fontsize=11)

    # Add business hours shading
    plt.axvspan(8, 18, alpha=0.1, color='green', zorder=0)

    # Add summary statistics
    total = len(df)
    peak_hour = hourly_data.idxmax() if not hourly_data.empty else 12
    peak_count = hourly_data.max() if not hourly_data.empty else 0

    # Info box
    plt.text(0.02, 0.98, f'Total Threats: {total}\nPeak Hour: {peak_hour:02d}:00 ({peak_count} threats)',
             transform=plt.gca().transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))

    # Grid and styling
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    # Save
    plt.savefig(OUT.parent / "anomaly_analysis.png", dpi=300, bbox_inches='tight')
    plt.close()

    print(f" Threat analysis complete: {total} threats detected")


def main():
    """
    Main execution pipeline for security log analysis.

    Loads data, runs 5 detection algorithms, generates reports and visualizations.
    Handles errors gracefully and provides detailed progress feedback.
    """
    try:
        # Load log data
        df = load_logs()
        print(f" Loaded {len(df)} log entries from {DATA}")

        # Initialize anomaly collection
        all_anomalies = []

        # Execute rule-based detectors
        print(" Running rule-based detectors...")
        all_anomalies.extend(detect_bruteforce(df))
        all_anomalies.extend(detect_suspicious_ips(df))
        all_anomalies.extend(detect_geo_hops(df, GEOIP_DB))
        all_anomalies.extend(detect_password_spraying(df))

        # Execute ML-based detector (if enabled)
        if ML_ENABLE:
            print(" Running ML behavioral analysis...")
            try:
                ml_anomalies = detect_ml_lof(df, contamination=ML_CONTAMINATION, window_min=ML_WINDOW_MIN)
                all_anomalies.extend(ml_anomalies)
                print(f"   Found {len(ml_anomalies)} ML anomalies")
            except Exception as e:
                print(f"⚠️  ML detection failed: {str(e)}")

        # Save results
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(all_anomalies, f, indent=2, ensure_ascii=False)

        print(f"✅ Total anomalies detected: {len(all_anomalies)}")
        print(f"📁 Results saved to: {OUT}")

        # Generate analytics (if anomalies found)
        if all_anomalies:
            print(" Generating analytics visualization...")
            plot_advanced_analytics(all_anomalies)
            print(f"📊 Visualization saved to: {OUT.parent / 'anomaly_analysis.png'}")
        else:
            print(" No anomalies detected - skipping visualization")

    except Exception as e:
        print(f"❌ Error in main execution: {str(e)}")
        raise

if __name__ == "__main__":
    main()
