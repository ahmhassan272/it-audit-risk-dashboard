import os
import numpy as np
import pandas as pd
from dateutil import parser
from datetime import datetime, timedelta

RAW_PATH = "data/raw/Access-Log-Anomaly-Detection-Dataset.csv"
PROCESSED_DIR = "data/processed"


def ensure_dirs():
    os.makedirs(PROCESSED_DIR, exist_ok=True)


def load_raw_logs():
    if not os.path.exists(RAW_PATH):
        raise FileNotFoundError(
            f"Expected raw dataset at {RAW_PATH}. "
            "Download 'Access-Log-Anomaly-Detection-Dataset.xls' from the public GitHub "
            "repository and place it in data/raw/."
        )

    df = pd.read_csv(RAW_PATH)

    df.columns = [c.strip().lower() for c in df.columns]

    required = [
        "timestamp",
        "masked_user",
        "source_ip",
        "destination_ip",
        "action",
        "resource",
        "device_type",
        "anomaly_score",
        "target",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing expected columns in dataset: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    df["date"] = df["timestamp"].dt.date
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.day_name()
    df["is_weekend"] = df["day_of_week"].isin(["Saturday", "Sunday"])
    df["is_off_hours"] = ~df["hour"].between(8, 18)

    for col in ["action", "resource", "device_type", "target"]:
        df[col] = df[col].astype(str).str.strip().str.lower()

    if "anomaly_score" in df.columns:
        df["anomaly_score"] = pd.to_numeric(df["anomaly_score"], errors="coerce")
        df["anomaly_score"] = df["anomaly_score"].fillna(df["anomaly_score"].median())
    else:
        df["anomaly_score"] = 0.0

    return df


def generate_users_table(logs: pd.DataFrame) -> pd.DataFrame:
    np.random.seed(42)

    users = pd.DataFrame(
        {"user_id": sorted(logs["masked_user"].astype(str).unique())}
    )

    departments = ["finance", "hr", "it", "operations", "sales"]
    roles = ["analyst", "manager", "engineer", "admin", "intern"]

    n = len(users)

    users["department"] = np.random.choice(departments, size=n, p=[0.2, 0.15, 0.25, 0.2, 0.2])
    users["role"] = np.random.choice(roles, size=n, p=[0.35, 0.15, 0.25, 0.1, 0.15])

    def assign_mfa(row):
        if row["role"] == "admin" or row["department"] == "it":
            return np.random.choice(["yes", "no"], p=[0.8, 0.2])
        return np.random.choice(["yes", "no"], p=[0.6, 0.4])

    users["mfa_enabled"] = users.apply(assign_mfa, axis=1)

    users["is_active"] = np.random.choice(["yes", "no"], size=n, p=[0.85, 0.15])

    today = datetime.today().date()
    start_date = today - timedelta(days=5 * 365)

    join_dates = [
        start_date + timedelta(days=int(x))
        for x in np.random.randint(0, 5 * 365, size=n)
    ]
    users["join_date"] = join_dates

    term_dates = []
    for _, row in users.iterrows():
        if row["is_active"] == "no":
            delta_days = np.random.randint(30, 5 * 365)
            term_date = row["join_date"] + timedelta(days=int(delta_days))
            if term_date > today:
                term_date = today - timedelta(days=np.random.randint(1, 365))
            term_dates.append(term_date)
        else:
            term_dates.append(pd.NaT)
    users["termination_date"] = term_dates

    managers = np.random.choice(users["user_id"], size=n)
    users["manager"] = managers

    return users


def generate_permissions_table(logs: pd.DataFrame, users: pd.DataFrame) -> pd.DataFrame:
    np.random.seed(43)

    systems = (
        logs["resource"]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
        .replace("", np.nan)
        .dropna()
        .unique()
    )
    systems = list(systems)
    if len(systems) == 0:
        systems = ["hr_portal", "finance_app", "crm", "admin_panel", "data_warehouse"]

    access_levels = ["read", "write", "admin"]

    rows = []
    for _, user in users.iterrows():
        num_systems = np.random.randint(1, min(5, len(systems)) + 1)
        granted = np.random.choice(systems, size=num_systems, replace=False)

        for sys in granted:
            if user["role"] == "admin" or user["department"] == "it":
                level = np.random.choice(access_levels, p=[0.3, 0.3, 0.4])
            else:
                level = np.random.choice(access_levels, p=[0.6, 0.3, 0.1])

            rows.append(
                {
                    "user_id": user["user_id"],
                    "system_name": sys,
                    "access_level": level,
                }
            )

    perms = pd.DataFrame(rows)
    return perms


def enrich_logs_with_users(logs: pd.DataFrame, users: pd.DataFrame) -> pd.DataFrame:
    enriched = logs.merge(
        users.rename(columns={"user_id": "masked_user"}),
        on="masked_user",
        how="left",
    )
    return enriched


def build_user_metrics(enriched_logs: pd.DataFrame) -> pd.DataFrame:
    grp = enriched_logs.groupby("masked_user")

    metrics = grp.agg(
        total_events=("timestamp", "count"),
        malicious_events=("target", lambda s: (s == "malicious").sum()),
        avg_anomaly_score=("anomaly_score", "mean"),
        max_anomaly_score=("anomaly_score", "max"),
        off_hours_events=("is_off_hours", lambda s: s.sum()),
        weekend_events=("is_weekend", lambda s: s.sum()),
        unique_sources=("source_ip", pd.Series.nunique),
        unique_devices=("device_type", pd.Series.nunique),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()

    metrics["off_hours_ratio"] = metrics["off_hours_events"] / metrics["total_events"]
    metrics["weekend_ratio"] = metrics["weekend_events"] / metrics["total_events"]

    return metrics


def build_risk_register(
    users: pd.DataFrame,
    perms: pd.DataFrame,
    metrics: pd.DataFrame,
) -> pd.DataFrame:
    u = users.copy()
    m = metrics.copy()
    u = u.rename(columns={"user_id": "masked_user"})
    merged = u.merge(m, on="masked_user", how="left")

    risk_rows = []

    def add_risk(user_row, risk_type, severity, description, evidence):
        risk_rows.append(
            {
                "masked_user": user_row["masked_user"],
                "department": user_row.get("department"),
                "role": user_row.get("role"),
                "risk_type": risk_type,
                "severity": severity,
                "description": description,
                "evidence": evidence,
            }
        )

    for _, row in merged.iterrows():
        if pd.notna(row.get("termination_date")) and row.get("is_active") == "yes":
            add_risk(
                row,
                "Ex-employee account still active",
                "High",
                "Account marked terminated but still active.",
                f"Termination date: {row['termination_date']}, is_active = yes",
            )

    admins = (
        perms[perms["access_level"] == "admin"]["user_id"].astype(str).unique().tolist()
    )
    admin_set = set(admins)

    for _, row in merged.iterrows():
        if row["masked_user"] in admin_set and row["mfa_enabled"] == "no":
            add_risk(
                row,
                "Admin account without MFA",
                "High",
                "User has admin-level access but no MFA enabled.",
                "access_level = admin, mfa_enabled = no",
            )

    for _, row in merged.iterrows():
        if pd.isna(row.get("malicious_events")):
            continue
        if row["malicious_events"] >= 3:
            add_risk(
                row,
                "Multiple malicious-labelled events",
                "High",
                "User associated with multiple events labelled as malicious.",
                f"malicious_events = {row['malicious_events']}",
            )
        elif 1 <= row["malicious_events"] < 3:
            add_risk(
                row,
                "Some malicious-labelled events",
                "Medium",
                "User associated with one or two malicious-labelled events.",
                f"malicious_events = {row['malicious_events']}",
            )

    for _, row in merged.iterrows():
        if pd.isna(row.get("max_anomaly_score")):
            continue
        if row["max_anomaly_score"] >= 0.9:
            add_risk(
                row,
                "Extreme anomaly score",
                "High",
                "User has at least one event with very high anomaly score.",
                f"max_anomaly_score = {row['max_anomaly_score']:.3f}",
            )
        elif row["avg_anomaly_score"] >= 0.6:
            add_risk(
                row,
                "Elevated anomaly behaviour",
                "Medium",
                "User's average anomaly score is elevated.",
                f"avg_anomaly_score = {row['avg_anomaly_score']:.3f}",
            )

    for _, row in merged.iterrows():
        if pd.isna(row.get("off_hours_ratio")):
            continue
        if row["off_hours_ratio"] >= 0.7 and row["total_events"] >= 20:
            add_risk(
                row,
                "Predominantly off-hours activity",
                "Medium",
                "Large share of user activity happens outside business hours.",
                f"off_hours_ratio = {row['off_hours_ratio']:.2f}, total_events = {row['total_events']}",
            )

    for _, row in merged.iterrows():
        if pd.isna(row.get("unique_sources")):
            continue
        if row["unique_sources"] >= 10:
            add_risk(
                row,
                "Many distinct IP addresses",
                "Medium",
                "User logged in from many different IP addresses.",
                f"unique_sources = {row['unique_sources']}",
            )

    cutoff = datetime.today() - timedelta(days=180)
    for _, row in merged.iterrows():
        if row["is_active"] == "yes" and pd.notna(row.get("last_seen")):
            if row["last_seen"] < cutoff:
                add_risk(
                    row,
                    "Dormant active account",
                    "Low",
                    "Active account with no recent activity (last 180 days).",
                    f"last_seen = {row['last_seen']}",
                )

    risk_df = pd.DataFrame(risk_rows)

    severity_score_map = {"High": 3, "Medium": 2, "Low": 1}
    risk_df["severity_score"] = risk_df["severity"].map(severity_score_map)

    return risk_df


def main():
    ensure_dirs()
    print("Loading raw logs...")
    logs = load_raw_logs()

    print("Generating users table...")
    users = generate_users_table(logs)

    print("Generating permissions table...")
    perms = generate_permissions_table(logs, users)

    print("Enriching logs with user attributes...")
    enriched_logs = enrich_logs_with_users(logs, users)

    print("Building user-level metrics...")
    metrics = build_user_metrics(enriched_logs)

    print("Building risk register...")
    risk_register = build_risk_register(users, perms, metrics)

    users.to_csv(os.path.join(PROCESSED_DIR, "users.csv"), index=False)
    perms.to_csv(os.path.join(PROCESSED_DIR, "permissions.csv"), index=False)
    enriched_logs.to_csv(os.path.join(PROCESSED_DIR, "logs_enriched.csv"), index=False)
    metrics.to_csv(os.path.join(PROCESSED_DIR, "user_metrics.csv"), index=False)
    risk_register.to_csv(os.path.join(PROCESSED_DIR, "risk_register.csv"), index=False)

    print("All done. Files written to data/processed/")
    print(risk_register.head())


if __name__ == "__main__":
    main()