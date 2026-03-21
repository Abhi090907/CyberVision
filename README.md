# CyberVision
# CyberVision X

### AI-Powered Cybersecurity, Computer Vision and DevSecOps Platform

---

## Overview

CyberVision X is a full-stack cybersecurity platform that integrates vulnerability scanning, artificial intelligence, computer vision, attack simulation, DevSecOps practices, and robotics-based response systems.

The platform is designed to go beyond traditional scanners by not only identifying vulnerabilities but also analyzing, validating, and responding to threats in an automated and intelligent manner.

---

## Demo

<!-- Add your demo video link below -->

<!-- Example: https://your-video-link.com -->

[ Demo Video Link Coming Soon ]

---

## Key Features

### Security Scanner

* Detection of OWASP Top 10 vulnerabilities
* HTTP security header analysis
* Integration with OWASP ZAP for active and passive scanning
* Risk scoring system (Critical, High, Medium, Low)

---

### AI and Computer Vision Engine

* Webpage screenshot analysis using OpenCV
* Detection of:

  * Phishing user interfaces
  * Fake login forms
  * Clickjacking overlays
* Annotated visual outputs with highlighted regions

---

### AI Security Advisor

* Converts scan results into:

  * Clear vulnerability explanations
  * Severity reasoning
  * Step-by-step remediation guidance
  * Code-level fixes (Python, JavaScript, HTTP headers)
* Supports OpenAI and Cohere (Command models)

---

### Attack Simulation Engine

* Simulates real-world attack scenarios:

  * Brute force login attempts
  * Input fuzzing (XSS, SQL injection payloads)
  * Session security testing
* Validates exploitability:

  * Confirmed
  * Potential
  * False Positive

---

### DevSecOps Integration

* Dockerized backend environment
* CI/CD pipeline using GitHub Actions
* Automated scans on code push
* Pipeline failure on high-risk vulnerabilities
* Asynchronous task handling using Celery and Redis

---

### Robotics Security Simulation

* ROS-based alert system
* Real-time anomaly response simulation
* Lightweight Gazebo environment integration

---

## Architecture

```text
Frontend (Tailwind UI)
        ↓
Django Backend (API Layer)
        ↓
Scanner → AI → Attack Engine
        ↓
Celery + Redis (Async Processing)
        ↓
OWASP ZAP / Computer Vision Models / LLM APIs
        ↓
ROS Nodes (Robotics Response)
```

---

## Tech Stack

### Backend

* Python
* Django and Django REST Framework
* Celery and Redis

### Security

* OWASP ZAP
* Custom OWASP vulnerability scanner

### AI and Machine Learning

* OpenCV
* TensorFlow (lightweight inference)
* OpenAI / Cohere APIs

### DevOps

* Docker and Docker Compose
* GitHub Actions (CI/CD)

### Robotics

* ROS (Robot Operating System)
* Gazebo

### Frontend

* HTML
* TailwindCSS
* Vanilla JavaScript

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Abhi090907/CyberVision.git
cd CyberVision
```

---

### 2. Setup Environment

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

---

### 3. Configure Environment Variables

Create a `.env` file based on `.env.example`:

```env
DJANGO_SECRET_KEY=your-secret-key
ZAP_API_KEY=your-zap-key
OPENAI_API_KEY=your-key
```

---

### 4. Run Backend

```bash
python manage.py migrate
python manage.py runserver
```

---

### 5. Start Redis and Celery

```bash
redis-server
celery -A config worker --loglevel=info
```

---

### 6. Run OWASP ZAP

```bash
zap.sh -daemon -port 8080 -config api.key=your-zap-key
```

---

### 7. Launch Frontend

```bash
cd frontend
python -m http.server 5500
```

Open in browser:

```
http://localhost:5500
```

---

## Usage Flow

1. Enter a target URL
2. Initiate a security scan
3. Analyze detected vulnerabilities
4. Review AI-generated recommendations
5. Execute attack simulations
6. Observe updated risk analysis
7. Optionally trigger robotics-based alert response

---

## Example Output

```json
{
  "risk_score": "High",
  "vulnerabilities": [
    {
      "type": "Missing CSP",
      "severity": "High",
      "fix": "Add Content-Security-Policy header"
    }
  ]
}
```

---

## Security Considerations

* All sensitive data is managed using environment variables
* No hardcoded API keys
* Attack simulations are designed to be non-destructive
* Intended strictly for ethical security testing and research

---

## Future Improvements

* Cloud deployment (AWS or GCP)
* Multi-user authentication system
* Advanced machine learning models
* Real-time monitoring and alerting dashboard
* Kubernetes-based scalability

---

## Contribution

Contributions are welcome.
Feel free to open issues or submit pull requests.

---

## License

This project is intended for educational and research purposes.

---

## Author

Abhishek Bijjargi
Aspiring Cybersecurity Engineer with interests in AI, DevSecOps, and system security

---

## Project Significance

CyberVision X integrates cybersecurity, artificial intelligence, DevSecOps, and robotics into a unified platform. It demonstrates how modern systems can move from passive vulnerability detection to intelligent, automated threat analysis and response.

---
