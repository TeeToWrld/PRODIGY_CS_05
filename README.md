# PRODIGY_CS_04
A Packet anaylzer tool for Mac OS

Perfect! Here’s a clean and professional README.md you can use for your packet analyzer project on GitHub:

⸻


#  Network Packet Analyzer (GUI-based)

A simple real-time network packet analyzer built using **Python**, **Scapy**, and **Tkinter**. It captures network packets on a specified interface and displays relevant information such as source IP, destination IP, protocol, and packet length in a graphical interface.

---



##  Features

- Real-time packet capture using Scapy
- GUI built with Tkinter
- Displays:
  - Serial Number
  - Source IP
  - Destination IP
  - Protocol
  - Length
- Start/Stop capture buttons
- Multi-threaded capture to keep UI responsive

---

##  Requirements

- Python 3.7+
- [Scapy](https://scapy.net)
- Works best on **macOS** and **Linux**

---

##  Installation

```bash

# Clone the repository
git clone https://github.com/YOUR_USERNAME/packet-analyzer.git
cd packet-analyzer

```

# Install dependencies
pip install scapy


⸻

## Usage

# Run the packet analyzer
sudo python3 analyzer.py

⚠️ sudo is required to access low-level packet capture on most systems.

⸻

## Interface Notes

	•	Default interface is set to "en0" (commonly Wi-Fi on macOS).
	•	You can change the interface in analyzer.py by modifying this line:

sniff(iface="en0", prn=packet_callback, store=0)

Use ifconfig (macOS/Linux) to check your active interfaces.

⸻

📁 Project Structure
packet-analyzer/
├── analyzer.py       
├── README.md
└── screenshot.png     


⸻

## Future Improvements

	•	Add packet filtering (e.g. only TCP/UDP/HTTP)
	•	Export to CSV
	•	Pause/resume capture
	•	Display more packet details on click

⸻

# Author

Gbemisola Ogunkanmbi
Email - gogunkanmbi@gmail.com

⸻

📜 License

This project is open-source and available under the MIT License.

---
