# 🌟Project : Network Sniffing Tool🔍
[![Project: Network Sniffing](https://r4.wallpaperflare.com/wallpaper/168/815/785/computer-the-room-hacker-the-world-at-night-wallpaper-3d3cd7535fdab5d1ca88d75fef1ecb67.jpg)](https://github.com/utkarshcse2026/Packet-Sniffing-Tool)


## This is a Description of my Project Where I Developed Two projects under the One Domain of Network Sniffing:

## 1. 🐍 Python-based Project ##
This Python script is designed to monitor HTTP traffic on a network interface using Scapy. It captures details such as protocol (TCP/UDP), IP addresses, ports, HTTP methods, paths, form data, and user-agent information. The captured requests are displayed in a structured table format, highlighting critical details for each request, including browser information and submitted form data.

## 2. 🖥️ Web-based Project ##
Create a script to capture HTTP requests from the specified website without permission.


## 🚀 Key Features

- **Real-time Monitoring:** Captures and displays HTTP requests and responses in real-time.
- **Detailed Analysis:** Provides comprehensive details like protocol types, IP addresses, ports, and HTTP header contents.
- **User-Agent Parsing:** Extracts and interprets browser and operating system information from user-agent strings.
- **Form Data Extraction:** Decodes and presents form submissions sent via HTTP POST requests.
- **Customizable Filtering:** Allows filtering of specific network traffic patterns for focused monitoring.

## 🔧 Requirements

- Python 3.x
- Scapy
- PrettyTable
- user_agents

## 📖 Usage

1. Run the script (`python networksniff.py`).
2. Observe HTTP traffic on the specified network interface.
3. Terminate monitoring by pressing Ctrl+C.

🔍 **HTTP Request Capturing Script**

🌐 **Website**: "http://testphp.vulnweb.com/login.php"

🖥️ **Supported Platforms**: Windows VS Code Editor

📝 **Objective**: Create a script to capture HTTP requests from the specified website without permission.


### Detailed Installation Instructions:

1. **Install Python:**
   - Make sure Python 3.x is installed on your system. If not, download it from [python.org](https://www.python.org/downloads/) and follow the installation prompts.

2. **Install Required Python Packages:**
   - Open your terminal or command prompt.
   - Use `pip`, Python's package installer, to install the necessary packages:
     ```
     pip install pyyaml ua-parser user-agents scapy prettytable
     ```
   - **Explanation of Packages:**
     - `scapy`: Allows manipulation and capturing of network packets.
     - `prettytable`: Facilitates the creation of formatted tables for displaying captured data.
     - `user_agents`: Parses user-agent strings to extract browser and operating system information.

### Detailed Usage Instructions:

1. **Clone the Repository:**
   - If you haven't already, clone or download the repository from GitHub where your script (`networksniff.py`) is hosted.

2. **Navigate to the Directory:**
   - Open a terminal or command prompt.
   - Change directory (`cd`) into the repository directory where `networksniff.py` is located.

3. **Run the Script:**
   - Execute the script using Python:
     ```
     python networksniff.py
     ```
   - Replace `networksniff.py` with the actual filename of your script.

4. **Capturing Network Packets:**
   - Once the script starts running, it will begin capturing HTTP requests made from your network interface.
   - Each captured HTTP request is parsed and displayed in a structured table format.

5. **Stopping the Script:**
   - To stop capturing packets, press `Ctrl+C` in the terminal or command prompt where the script is running.
   - This action terminates the script execution and stops further packet capture.

### Example Usage:

- Upon running `networksniff.py`, the script displays a banner using ASCII art.
- It listens and captures HTTP requests in real-time.
- Each captured HTTP request includes details such as timestamp, protocol (TCP/UDP), IP addresses, ports, HTTP method, path, website, browser info, and form data (if applicable) in a neatly formatted table.

### Additional Notes:

- **Permissions:** Ensure your environment has the necessary permissions to capture network packets. Administrative privileges might be required, depending on your operating system.

### Images :

1) Python Based Network Sniffer Tool : `networksniff.py`

2) Web Based Network Sniffer Tool : `Web_based_Sniffer_Tool.php`

3)   
## 🌐 Explore More


## By Utkarsh Aggarwal : 

Check out the [GitHub](https://github.com/utkarshcse2026/Packet-Sniffing-Tool) for detailed documentation, issues, and contributions.

---

Enhance your network monitoring capabilities with CodeAlpha Project's Network Sniffing tool! Feel free to customize and expand this README.md further to showcase more details, screenshots, or additional features of your project.
