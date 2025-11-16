# Automated IT Audit Risk Dashboard (Python + Power BI)

This repository contains an end-to-end IT audit analytics project designed for your CV / portfolio.

It uses a **real, public enterprise-style access log dataset** (Access-Log-Anomaly-Detection-Dataset)
and builds:
- Synthetic but realistic user and permissions data
- User-level behaviour metrics
- An IT risk register with severities (High/Medium/Low)
- A structure ready for a Power BI report and screenshots

## 1. Folder structure

```text
it-audit-risk-dashboard/
├─ data/
│  ├─ raw/
│  │  └─ Access-Log-Anomaly-Detection-Dataset.xls    # you download this
│  ├─ processed/
│  │  ├─ logs_enriched.csv
│  │  ├─ users.csv
│  │  ├─ permissions.csv
│  │  └─ risk_register.csv
├─ src/
│  └─ build_risk_register.py
├─ reports/
│  ├─ powerbi/
│  │  └─ screenshots/
│  │     ├─ overview_dashboard.png
│  │     ├─ risks_by_severity.png
│  │     ├─ risks_by_department.png
│  │     ├─ top_risky_users.png
│  │     └─ user_detail_page.png
├─ requirements.txt
├─ .gitignore
└─ README.md
```

> Note: the actual Power BI `.pbix` file is not included because it must be created
> on a Windows machine running Power BI Desktop, using the processed CSVs. The
> repo is fully prepared so you (or an interviewer) can easily build it.

## 2. Dataset

Download the Excel file named something like:

> `Access-Log-Anomaly-Detection-Dataset.xls`

from the public GitHub project that hosts it (search the name on GitHub),
and place it in:

```text
data/raw/Access-Log-Anomaly-Detection-Dataset.xls
```

The dataset contains:
- `timestamp`, `masked_user`, `source_ip`, `destination_ip`
- `action`, `resource`, `device_type`
- `anomaly_score`, `target` (benign/malicious)

## 3. How to run the pipeline

Create and activate a virtual environment (optional but recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # Mac / Linux
# or: venv\Scripts\activate  # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the processing script:

```bash
python src/build_risk_register.py
```

If the raw dataset file is in the correct location, this will create:

- `data/processed/users.csv`
- `data/processed/permissions.csv`
- `data/processed/logs_enriched.csv`
- `data/processed/user_metrics.csv`
- `data/processed/risk_register.csv`

These CSVs are exactly what you will connect to from Power BI.

## 4. IT audit logic implemented

The script simulates several **IT General Controls / access review** checks, such as:

- **Ex-employee account still active**  
  User has a termination date but `is_active = yes` (High severity).

- **Admin account without MFA**  
  User appears in permissions as having admin access, but `mfa_enabled = no` (High).

- **Multiple malicious-labelled events**  
  User is associated with several events labelled as malicious in the dataset (High/Medium).

- **Extreme / elevated anomaly scores**  
  User has very high maximum anomaly score or high average anomaly score (High/Medium).

- **Predominantly off-hours activity**  
  Majority of activity outside 08:00–18:00 if user has enough events (Medium).

- **Many distinct IP addresses used**  
  Could indicate credential sharing or risky behaviour (Medium).

- **Dormant but active accounts**  
  Active account with no activity in the last 180 days (Low).

Each finding is turned into a risk record with:
- `risk_type`
- `severity`
- `description`
- `evidence`
- `severity_score` (numeric mapping of severity for reporting)

## 5. Power BI (or Tableau) report

Because Power BI Desktop runs only on Windows, the actual `.pbix` file and UI
cannot be generated directly here. However, you or a reviewer can:

1. Open Power BI Desktop on Windows.
2. Use **Get Data → Text/CSV** to load all CSVs in `data/processed/`.
3. Create relationships:
   - `users.user_id` ↔ `risk_register.masked_user`
   - `users.user_id` ↔ `permissions.user_id`
   - `users.user_id` ↔ `logs_enriched.masked_user`
4. Build visuals such as:
   - KPI cards: total risks, high risks, users with risks, admins without MFA
   - Bar charts: risks by severity, risks by department, risks by type
   - Table: top risky users (user, department, role, risk_type, severity)
   - Drillthrough page: per-user event timeline and risk details.

The `reports/powerbi/screenshots/` folder contains placeholder PNGs that you
can replace with real screenshots from Power BI once you build the report.

## 6. How to use this in your CV / portfolio

You can describe this project as:

> *Automated IT Audit Risk Dashboard (Python, Power BI)*  
> • Used a public enterprise access-log dataset to simulate an IT access review across many users and events.  
> • Built a Python pipeline (pandas) to enrich logs with synthetic user and permissions data, derive behaviour metrics, and generate an IT risk register (high/medium/low severity).  
> • Implemented audit rules for admin accounts without MFA, ex-employee accounts still active, anomalous access behaviour, off-hours activity, dormant accounts, and excessive IP usage.  
> • Designed a Power BI report concept with risk KPIs, department breakdowns, and user-level drilldowns suitable for ITGC / access management reviews.

You can push this repo to GitHub and link it directly in your CV and LinkedIn.