# 🔒 QR-Shield: Anti-Quishing Fraud Defense Engine for Nepal Bank and Wallet 

QR-Shield is a standalone, mobile-responsive computer vision application built using Python, Streamlit, and OpenCV. It operates as a defensive mechanism to combat the growing epidemic of **Quishing** (QR Code Phishing) financial fraud across digital payment networks.

The system decodes matrix codes via image uploads or real-time camera captures, parses the payload strings through a heuristic rules matrix, and flags high-risk indicators (such as domain typosquatting, unauthorized short-links, or obfuscated redirects) before a user interacts with a financial transaction point.

## 🌟 Core Implementation Capabilities
* **Matrix Detection Layer:** Processes camera frames or file buffers natively using `pyzbar` and binary conversion algorithms.
* **Fintech Heuristics Architecture:** Evaluates targets against standard network specs (e.g., native eSewa, Khalti, or fonepay deep-links) and blocks unrecognized or suspicious third-party processing gateways.
* **Data-Minimized Sandbox:** Runs fully client-side on memory buffers—no user images, tracking details, or transaction parameters are saved or stored.

---

## 🚀 Local Setup & Verification Workflow

Follow these steps to clone this project archive and run it within a local sandbox environment.

### Prerequisites
Ensure your system environment is provisioned with **Python 3.8+** and **Git**.

### 1. Clone the Target Codebase
Open your shell terminal or Windows PowerShell window and clone the directory:
```bash
git clone [https://github.com/Sangharsa-adk/QR-shield.git](https://github.com/Sangharsa-adk/QR-shield.git)
cd QR-shield
