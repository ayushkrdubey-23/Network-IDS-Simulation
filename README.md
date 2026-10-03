# Network Intrusion Detection System (IDS) Simulation

A defensive, machine-learning-assisted Network Intrusion Detection System simulation that analyzes synthetic network traffic, identifies suspicious activity, calculates risk scores, and manages security alerts through a React-based Security Operations Center (SOC) dashboard.

## Project Overview

The Network IDS Simulation demonstrates how multiple detection approaches can work together to identify potentially suspicious network behavior.

The system uses:

* Synthetic network traffic generation
* Network feature extraction
* Configurable signature-based detection
* Statistical anomaly detection
* Machine learning classification
* Hybrid risk scoring
* Alert and incident management
* FastAPI backend
* React SOC dashboard
* SQLite database

**Important:** This is an educational simulation using synthetic traffic records. It does not capture live network packets, scan external systems, or provide production-grade network protection.

## Key Features

### Detection Engine

* Generates synthetic normal and suspicious network traffic.
* Extracts network traffic features.
* Applies configurable signature rules.
* Detects statistical anomalies using z-scores.
* Uses Logistic Regression, Random Forest, and Isolation Forest.
* Combines detection evidence into a hybrid risk score.

### Risk Classification

| Risk Level | Risk Score |
| ---------- | ---------: |
| INFO       |       0–24 |
| LOW        |      25–49 |
| MEDIUM     |      50–74 |
| HIGH       |     75–100 |

### Alert and Incident Management

* View generated security alerts.
* Filter alerts by risk level and status.
* Update alert investigation status.
* Add analyst notes.
* Create security incidents.
* Link alerts to incidents.
* View alert statistics.

### SOC Dashboard

* React-based security monitoring interface.
* Overview of alert statistics.
* Alert management and filtering.
* Incident management.
* Risk visualization and charts.
* Backend API integration.

## Technology Stack

| Component            | Technologies   |
| -------------------- | -------------- |
| Programming Language | Python         |
| Backend              | FastAPI        |
| Frontend             | React 19, Vite |
| Database             | SQLite         |
| Data Processing      | Pandas, NumPy  |
| Machine Learning     | Scikit-learn   |
| Model Storage        | Joblib         |
| Data Visualization   | Recharts       |
| Icons                | Lucide React   |
| API Testing          | Pytest, HTTPX  |
| Version Control      | Git, GitHub    |

## System Architecture

```text
             Synthetic Traffic
                     |
                     v
          Dataset Generation
                     |
                     v
             Feature Extraction
                     |
          +----------+----------+
          |          |          |
          v          v          v
      Signature   Statistical   Machine
      Detection   Anomaly       Learning
                  Detection     Models
          |          |          |
          +----------+----------+
                     |
                     v
              Hybrid Detection
                     |
                     v
              Risk Classification
                     |
                     v
              Alert Management
                     |
                     v
                SQLite DB
                     |
                     v
                FastAPI
                     |
                     v
              React SOC Dashboard
```

## Project Structure

```text
Network-IDS-Simulation/
│
├── backend/
│   ├── models/
│   ├── routes/
│   ├── services/
│   └── utils/
│
├── data/
│
├── docs/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── ids/
│   ├── feature_extractor.py
│   ├── signature_engine.py
│   ├── signature_rules.json
│   ├── anomaly_detector.py
│   └── hybrid_engine.py
│
├── ml/
│   └── train_models.py
│
├── models/
│
├── reports/
│   └── ml_evaluation.json
│
├── screenshots/
│
├── simulator/
│   └── generate_dataset.py
│
├── tests/
│   ├── conftest.py
│   ├── test_alert_service.py
│   ├── test_anomaly_detector.py
│   ├── test_api.py
│   ├── test_feature_extractor.py
│   ├── test_hybrid_engine.py
│   └── test_signature_engine.py
│
├── .gitignore
├── .env.example
├── README.md
├── requirements.txt
└── verify_database.py
```

## Installation and Setup

### Prerequisites

Install the following:

* Python 3.10 or later
* Node.js and npm
* Git
* Visual Studio Code (recommended)

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Network-IDS-Simulation
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a Python virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Python dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Start the FastAPI backend

From the project root:

```powershell
python -m uvicorn backend.main:app --reload
```

Backend address:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

Health endpoint:

```text
http://127.0.0.1:8000/api/health
```

### 5. Start the React frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local frontend address printed by Vite, normally:

```text
http://localhost:5173
```

Keep both backend and frontend terminals running while using the dashboard.

## API Endpoints

The backend provides the following endpoints:

| Method | Endpoint                                         | Purpose                      |
| ------ | ------------------------------------------------ | ---------------------------- |
| GET    | `/`                                              | API welcome message          |
| GET    | `/api/health`                                    | Backend and database health  |
| GET    | `/api/alerts`                                    | Retrieve and filter alerts   |
| GET    | `/api/alerts/{alert_id}`                         | Retrieve an alert            |
| GET    | `/api/statistics`                                | Alert statistics             |
| PATCH  | `/api/alerts/{alert_id}/status`                  | Update alert status          |
| POST   | `/api/incidents`                                 | Create an incident           |
| POST   | `/api/incidents/{incident_id}/alerts/{alert_id}` | Link an alert to an incident |

Full interactive documentation is available at `/docs`.

## Machine Learning Evaluation

The project evaluates three models using the synthetic dataset.

The following results are recorded in `reports/ml_evaluation.json`:

| Model               | Accuracy | Precision |  Recall | F1-score |
| ------------------- | -------: | --------: | ------: | -------: |
| Logistic Regression |  100.00% |   100.00% | 100.00% |  100.00% |
| Random Forest       |  100.00% |   100.00% | 100.00% |  100.00% |
| Isolation Forest    |   66.63% |    97.37% |  25.28% |   40.14% |

The evaluation report also contains confusion matrices and classification reports.

**Evaluation limitation:** These metrics are based on generated synthetic traffic. The synthetic scenarios may contain patterns that are relatively easy for supervised models to learn, so perfect scores do not establish real-world generalization. Independent datasets, more realistic traffic variation, and further validation would be required before considering deployment in a real environment.

## Automated Testing

The project includes automated tests for:

* Feature extraction and input validation
* Signature rule loading and matching
* Statistical anomaly detection
* Hybrid risk scoring
* Alert and incident database operations
* FastAPI endpoint behavior

Run the complete test suite:

```powershell
python -m pytest -v
```

### Latest Test Results

| Metric         |       Result |
| -------------- | -----------: |
| Total tests    |          164 |
| Passed         |          164 |
| Failed         |            0 |
| Execution time | 7.14 seconds |

Python compilation verification:

```powershell
python -m compileall backend ids ml simulator tests
```

Frontend production build:

```powershell
cd frontend
npm run build
```

These results reflect the project's verification run on October 3, 2026.

## Screenshots

Screenshots of the SOC dashboard and its features can be added to the `screenshots/` directory.

Suggested screenshots:

* Dashboard overview
* Security alert listing
* Alert filtering
* Alert investigation and status update
* Incident management
* Incident and alert linking
* API documentation
* Risk analytics

Once screenshots are added, reference them here using their actual filenames.

## Defensive Simulation and Safety

This project is designed for educational and defensive cybersecurity learning.

* Uses synthetic network flow records.
* Uses reserved documentation IP address ranges in generated examples.
* Does not capture live network packets.
* Does not scan or probe external systems.
* Does not exploit vulnerabilities or interact with third-party systems.

The results are intended for demonstration, experimentation, and learning.

## Future Improvements

* Add more realistic synthetic network scenarios.
* Improve anomaly detection and suspicious-class recall.
* Validate models against independent, authorized datasets.
* Introduce explainable AI for detection decisions.
* Improve frontend code splitting and dashboard performance.
* Add more detailed security investigation reports.
* Expand automated testing and documentation.

## Author

**Ayush Kumar Dubey**

GitHub: [ayushkrdubey-23](https://github.com/ayushkrdubey-23)

## License

A license has not yet been specified. Add a suitable `LICENSE` file before presenting this repository as an open-source project.

