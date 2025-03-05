# Simple Web Vulnerability Scanner

A **Command-Line Web Vulnerability Scanner** built in Python to scan websites for **SQL Injection, XSS, Directory Traversal**, and **Subdomain Enumeration** with **Tor & Proxy support** for anonymous scanning. The tool also generates an **HTML report** with the results.

## 🚀 Features
- ✅ **SQL Injection Detection**
- ✅ **XSS (Cross-Site Scripting) Detection**
- ✅ **Directory Traversal Scanner**
- ✅ **Subdomain Enumeration (crt.sh method)**
- ✅ **Tor & Proxy Support (Anonymous Scanning)**
- ✅ **HTML Report Generation**

## 🔧 Installation
### 1️⃣ **Clone the Repository**
```bash
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner
```
### 2️⃣ **Install Dependencies**
```bash
pip install -r requirements.txt
```
### 3️⃣ **(Optional) Enable Tor for Anonymous Scanning**
Ensure that **Tor service** is running:
```bash
sudo service tor start
```

## 🛠 Usage
### 🔹 **Basic Scanning**
```bash
python scanner.py http://example.com
```
### 🔹 **Use Tor for Anonymous Scanning**
```bash
python scanner.py http://example.com --proxy
```
### 🔹 **Enable Subdomain Enumeration**
```bash
python scanner.py http://example.com --subdomains
```

## If you want use With GUI 

### 🔹**Use Gui_Scanner.py**

```bash
python Gui_Scanner.py
```

### 🔹Then paste link in inputbox and check for attacks check 


## 📄 Example Output
```
[+] Scanning for SQL Injection...
[+] Scanning for XSS...
[+] Checking for Directory Traversal...
[+] Enumerating subdomains...
[+] Report saved as report.html
```

## 📊 Report Generation
The scan results are saved in an **HTML report (report.html)** format.

## 🖥️ GUI Screenshots
![App Screenshot](assets/image.png)


## 🔥 Author
- **Ayush Gangwar**  
- GitHub: [Arya182-ui](https://github.com/Arya182-ui)  
- LinkedIn: [Ayush Gangwar](https://www.linkedin.com/in/ayush-gangwar-3b3526237)

## ☕ Support Me

Do you like My projects? You can show your support by buying me a coffee! Your contributions motivate me to keep improving and building more awesome projects. 💻❤  
[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](http://buymeacoffee.com/Arya182)

---

## ⚠ Disclaimer
This tool is intended for educational purposes only. Use it **only on websites you own or have permission to test**. Unauthorized scanning may be illegal.

---
💡 **Suggestions & Contributions are Welcome!** 🚀
