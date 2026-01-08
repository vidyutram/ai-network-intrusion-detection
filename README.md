# AI-Based Network Intrusion Detection System (NIDS)

An end-to-end AI-driven Network Intrusion Detection System that captures live network packets, analyzes traffic using machine learning, and detects malicious activity in real time.

## 🔍 Problem Statement
Traditional security systems struggle to detect modern network attacks in real time. This project aims to build an intelligent IDS using machine learning to classify network traffic as normal or malicious.

## 💡 Solution
The system integrates packet capture, feature extraction, machine learning-based classification, and real-time inference through a backend service.

## 🛠 Tech Stack
- Python
- Scikit-learn
- Pandas, NumPy
- NSL-KDD Dataset
- FastAPI (for inference)
- Scapy (for packet capture)

## ⚙️ Features
- Live packet capture
- ML-based attack classification
- Model evaluation (ROC-AUC, Confusion Matrix)
- Simulated attack traffic
- Modular pipeline design

## 📊 Results
- High classification accuracy on NSL-KDD dataset
- ROC-AUC score printed during evaluation

## ▶️ How to Run

```bash
pip install -r requirements.txt
python train.py
python serve.py


📌 This README alone makes your repo **internship-ready**.

---

## 3️⃣ Initialize Git in VS Code

Open **Terminal** in VS Code:

```bash
git init
