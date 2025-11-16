🚀 IT Audit Risk Analytics Pipeline (Python)

This project is an end-to-end IT Audit Analytics solution that processes enterprise-style access logs, generates user and permission metadata, applies audit rules, and produces a full IT risk register ready for dashboarding (Power BI / Tableau).

It simulates a real-world IT General Controls (ITGC) access review using a public dataset, automated Python pipeline, and well-defined audit logic.

⸻

📁 Project Structure
it-audit-risk-dashboard/
│
├── data/
│   ├── raw/                     # Place the downloaded dataset here
│   └── processed/               # Output from the Python pipeline
│
├── src/
│   └── build_risk_register.py   # Main pipeline script
│
├── reports/
│   └── powerbi/
│       └── screenshots/         # Example visualisations (placeholder)
│
├── README.md
└── requirements.txt

📊 Dataset

This project uses the Access-Log-Anomaly-Detection Dataset, a public enterprise-style access log dataset that includes:
	•	Timestamps
	•	Masked user IDs
	•	Source & destination IPs
	•	Device types
	•	Resource paths
	•	Actions (modify, login, delete, etc.)
	•	Anomaly scores
	•	Labels (benign/malicious)

Download the CSV file from the dataset’s GitHub repository and place it here:
data/raw/Access-Log-Anomaly-Detection-Dataset.csv

⚙️ Pipeline Overview

The processing script performs the following steps:

1. Load and clean access logs
	•	Normalises column names
	•	Parses timestamps
	•	Adds behaviour features:
	•	hour of day
	•	weekend flag
	•	off-hours flag
	•	day of week

⸻

2. Generate synthetic user master data

Based on the users in the log dataset, the pipeline creates a realistic user table containing:
	•	Department
	•	Role (analyst, engineer, admin, etc.)
	•	MFA enabled (yes/no)
	•	Active / terminated status
	•	Join & termination dates
	•	Assigned manager

This approximates data typically stored in HR systems / IAM tools.

⸻

3. Generate system permissions

Each user is randomly assigned:
	•	A set of systems (derived from resource names)
	•	Access levels (read / write / admin)

Admins and IT staff have a higher probability of admin rights.

⸻

4. Enrich logs with user attributes

Logs are joined with the generated user metadata to form a unified event table:
	•	User behaviour over time
	•	Device and IP usage
	•	Off-hours patterns
	•	Malicious events

⸻

5. Build user-level behaviour metrics

Metrics include:
	•	Total events
	•	Malicious-labelled events
	•	Average & max anomaly score
	•	Off-hours activity ratio
	•	Unique IP addresses used
	•	Unique devices used
	•	Last seen timestamp

⸻

6. Generate IT audit findings (Risk Register)

The pipeline applies real-world IT audit rules, including:

🔐 Access Management Risks
	•	Admin accounts without MFA
	•	Excessive permissions
	•	Ex-employee accounts still active

🕒 Logging & Monitoring Risks
	•	Multiple malicious-labelled events
	•	High anomaly scores
	•	Heavy off-hours activity
	•	Many distinct IP addresses (possible shared credentials)

💤 Dormant Accounts
	•	Accounts active but not used for >180 days

Each finding includes:
	•	User ID
	•	Department & role
	•	Risk type
	•	Severity (High/Medium/Low)
	•	Description
	•	Evidence
	•	Numeric severity score

The output is saved to:
data/processed/risk_register.csv

📈 Dashboarding (Power BI / Tableau)

Although Power BI Desktop requires Windows, the produced CSVs can be visualised using:
	•	Power BI Desktop
	•	Tableau Public (recommended for Mac users)
	•	Looker Studio

Suggested visuals include:
	•	Risks by severity
	•	Risks by department
	•	Risks by type
	•	High-risk users
	•	Off-hours activity metrics
	•	Drill-through per-user risk profiles

Placeholder screenshots are included in:
reports/powerbi/screenshots/

🛠️ How to Run
python3 -m venv venv
source venv/bin/activate        # Mac / Linux
pip install -r requirements.txt
python src/build_risk_register.py

🎯 Purpose of This Project

This project demonstrates skills relevant to:
	•	IT Audit
	•	Cybersecurity Audit
	•	Data Analytics
	•	Access Management
	•	IT General Controls (ITGC)
	•	Python for data automation
	•	BI dashboard design

It is designed to simulate the kind of analytics work performed in:
	•	Big 4 IT Audit teams
	•	Cybersecurity consulting
	•	Risk & Compliance analytics
	•	Security Operations (SOC) reporting

⸻

📌 Key Skills Demonstrated
	•	Python (pandas, data processing)
	•	Designing audit logic & controls
	•	Building synthetic user / permissions models
	•	Log enrichment & behavioural analytics
	•	Risk scoring methodology
	•	End-to-end pipeline design
	•	Dashboard-ready data modelling
