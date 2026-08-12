# Apoliak Vitals

## Project Brief for AI Code Assistant

This file describes the full project plan for **Apoliak Vitals**.

The goal is to build a clean, safe, and useful Windows PC analysis tool.  
This tool will later become the first module of a bigger project called **Apoliak Optimizer**.

---

# 1. Project Name

```text
Apoliak Vitals
```

Alternative name:

```text
Apoliak Optimizer - Analyze PC Module
```

---

# 2. Project Description

**Apoliak Vitals** is a lightweight Windows tool that analyzes the current state of a PC and generates a clear system report.

The tool should check basic performance and system health information such as:

- CPU information
- RAM usage
- Disk usage
- Windows version
- Running processes
- System uptime
- Temporary files size
- Basic recommendations
- PC Health Score

This project should be safe.  
The first version must only analyze the PC and display recommendations.  
It must not change Windows settings yet.

Main philosophy:

> Every tweak is explained. Every change is reversible.

---

# 3. Main Goal

Build a console-based Python application that runs on Windows and shows a complete PC analysis report.

The first version should be simple, stable, readable, and easy to expand.

The tool should answer these questions:

- What Windows version is the user running?
- What CPU does the user have?
- How much RAM is installed?
- How much RAM is currently being used?
- How much disk space is free?
- How many processes are running?
- How large is the TEMP folder?
- How long has the PC been running?
- Does the PC look healthy or does it need optimization?
- What basic recommendations should the user follow?

---

# 4. Technology Stack

Use **Python** for the first version.

Recommended Python modules:

```text
psutil
platform
os
shutil
time
datetime
subprocess
```

Optional module for future GUI:

```text
customtkinter
```

The first release should be a console application.  
A GUI version can be added later.

---

# 5. Project Versions

## v0.1 - Console PC Analyzer

The first version should run in the terminal.

Required features:

- Show application title
- Detect system information
- Detect CPU information
- Detect RAM information
- Detect disk information
- Count running processes
- Detect system uptime
- Calculate TEMP folder size
- Show basic recommendations

---

## v0.2 - Report Export

Add the ability to export the analysis result into a text file:

```text
pc_report.txt
```

The report should include:

- Date and time of analysis
- System information
- CPU information
- RAM information
- Disk information
- Running process count
- TEMP folder size
- System uptime
- Recommendations
- PC Health Score

---

## v0.3 - PC Health Score

Add a simple score from 0 to 100.

Example output:

```text
PC Health Score: 76/100
Status: Needs Optimization
```

Suggested scoring rules:

| Problem | Penalty |
|---|---:|
| RAM usage above 80% | -20 |
| CPU usage above 70% | -15 |
| Less than 20 GB free space on C drive | -20 |
| More than 180 running processes | -10 |
| TEMP folder larger than 3 GB | -10 |
| System uptime longer than 48 hours | -5 |

Score status:

| Score | Status |
|---:|---|
| 90 - 100 | Excellent |
| 75 - 89 | Good |
| 50 - 74 | Needs Optimization |
| 0 - 49 | Poor |

---

## v0.4 - Recommendations Engine

Add recommendations based on analysis results.

Examples:

```text
RAM usage is high. Close unnecessary background apps.
```

```text
Temporary files are taking too much space. Cleaning them may free disk space.
```

```text
Too many processes are running. Check startup apps.
```

```text
Your PC has been running for a long time. Restarting may improve performance.
```

```text
Low free disk space detected. Free up space on your C drive.
```

---

## v1.0 - GUI Version

Add a modern GUI using:

```text
CustomTkinter
```

The GUI should include:

- Analyze PC button
- System information section
- CPU section
- RAM section
- Disk section
- PC Health Score
- Recommendations section
- Export Report button
- Modern dark UI design

---

# 6. Required Features for First Version

## 6.1 System Info

The program should detect:

- Operating system name
- Windows release
- Windows version/build
- Architecture
- Processor name

Example output:

```text
System: Windows 11
Release: 11
Version: 10.0.22631
Architecture: AMD64
Processor: AMD Ryzen 5 5600
```

---

## 6.2 CPU Info

The program should detect:

- Physical CPU cores
- Logical CPU cores
- Current CPU usage percentage

Example output:

```text
CPU Cores: 6 physical / 12 logical
CPU Usage: 14%
```

---

## 6.3 RAM Info

The program should detect:

- Total RAM
- Available RAM
- Used RAM
- RAM usage percentage

Example output:

```text
Total RAM: 16 GB
Available RAM: 5.2 GB
Used RAM: 10.8 GB
RAM Usage: 67%
```

---

## 6.4 Disk Info

The program should detect information for drive C:

- Total disk size
- Used disk space
- Free disk space
- Disk usage percentage

Example output:

```text
Total Disk: 512 GB
Used Disk: 390 GB
Free Disk: 122 GB
Disk Usage: 76%
```

---

## 6.5 Running Processes

The program should count currently running processes.

Example output:

```text
Running Processes: 164
```

---

## 6.6 TEMP Folder Size

The program should calculate the size of the user's TEMP folder.

Example output:

```text
Temp Folder Size: 3.4 GB
```

The function should skip files that cannot be accessed instead of crashing.

---

## 6.7 System Uptime

The program should calculate how long the PC has been running since last boot.

Example output:

```text
System Uptime: 12h 45m
```

---

## 6.8 Recommendations

The program should generate recommendations based on the results.

Example output:

```text
Recommendations:
- RAM usage is high. Close unnecessary background apps.
- Temporary files can be cleaned.
- Too many processes are running.
```

---

# 7. Example Final Console Output

```text
====================================
        Apoliak Vitals
====================================

System: Windows 11
Version: 10.0.22631
Architecture: AMD64
Processor: AMD Ryzen 5 5600

--- CPU ---
CPU Cores: 6 physical / 12 logical
CPU Usage: 12%

--- RAM ---
Total RAM: 16 GB
Available RAM: 4.8 GB
RAM Usage: 70%

--- Disk ---
Total Disk: 512 GB
Used Disk: 420 GB
Free Disk: 92 GB
Disk Usage: 82%

--- Processes ---
Running Processes: 168

--- Temp Files ---
Temp Folder Size: 2.8 GB

--- Uptime ---
System Uptime: 9h 22m

--- PC Health Score ---
Score: 82/100
Status: Good

--- Recommendations ---
- Temporary files can be cleaned.
- Check startup apps if your PC feels slow.
- Restart your PC before gaming for better performance.
```

---

# 8. Suggested Project Structure

```text
Apoliak-Vitals/
│
├── src/
│   ├── analyzer.py
│   ├── recommendations.py
│   ├── health_score.py
│   ├── report.py
│   └── utils.py
│
├── docs/
│   └── roadmap.md
│
├── screenshots/
│   └── preview.png
│
├── main.py
├── requirements.txt
├── README.md
├── PROJECT_PLAN.md
├── LICENSE
└── .gitignore
```

---

# 9. File Responsibilities

## main.py

Main application entry point.

Responsibilities:

- Start the program
- Call analyzer functions
- Call health score function
- Call recommendation function
- Print final report
- Ask user if they want to export report

---

## src/analyzer.py

Contains functions for collecting PC information.

Suggested functions:

```python
get_system_info()
get_cpu_info()
get_ram_info()
get_disk_info()
get_process_count()
get_temp_size()
get_uptime()
analyze_pc()
```

---

## src/recommendations.py

Contains recommendation logic.

Suggested function:

```python
generate_recommendations(data)
```

This function should return a list of recommendation strings.

---

## src/health_score.py

Contains PC Health Score logic.

Suggested function:

```python
calculate_health_score(data)
```

This function should return:

- score number
- status text

---

## src/report.py

Contains report export logic.

Suggested function:

```python
export_report(data, recommendations, score, status)
```

The report should be saved as:

```text
pc_report.txt
```

---

## src/utils.py

Contains helper functions.

Suggested functions:

```python
bytes_to_gb(value)
format_uptime(seconds)
safe_get_folder_size(path)
```

---

# 10. First Task for AI Code Assistant

Build the first working console version of **Apoliak Vitals**.

The program must:

1. Display the application title
2. Collect system information
3. Collect CPU information
4. Collect RAM information
5. Collect disk information
6. Count running processes
7. Calculate TEMP folder size
8. Calculate system uptime
9. Calculate PC Health Score
10. Generate recommendations
11. Print everything in a clean format
12. Ask the user if they want to export the report
13. Save the report as `pc_report.txt` if the user agrees

---

# 11. Safety Rules

The first version must not:

- Disable Windows Defender
- Disable Windows Update
- Change registry settings
- Delete files without confirmation
- Disable Windows services
- Modify system settings
- Promise FPS boost
- Make irreversible changes
- Run dangerous commands

The first version should only analyze and recommend.

---

# 12. Future Features

Possible future features:

- GUI version
- TEMP cleaner with user confirmation
- Startup apps manager
- Power plan switcher
- Gaming mode profile
- Export report to JSON
- Export report to PDF
- Benchmark before and after optimization
- Game profiles for specific games
- Integration into Apoliak Optimizer
- Restore point creation before any optimization
- Safe mode and advanced mode
- Plugin system for future modules

---

# 13. Roadmap

## Phase 1

- Create console analyzer
- Show basic system information
- Add recommendations
- Add health score

## Phase 2

- Split project into modules
- Add report export
- Improve README
- Add screenshots

## Phase 3

- Create GUI
- Add Analyze PC button
- Add modern dark design
- Add report export through GUI

## Phase 4

- Connect project to Apoliak Optimizer
- Add safe optimization features
- Add restore system

---

# 14. README Short Description

Use this text in README.md:

```text
Apoliak Vitals is a lightweight Windows PC analysis tool that checks system health, CPU usage, RAM usage, disk space, running processes, temporary files, uptime, and provides simple optimization recommendations.

This project is the first module of Apoliak Optimizer.
```

---

# 15. GitHub Repository Description

```text
A lightweight Windows PC analyzer and first module of Apoliak Optimizer.
```

---

# 16. Suggested GitHub Topics

```text
python
windows
windows-11
pc-optimizer
system-info
gaming
performance
analyzer
desktop-tool
apoliak
```

---

# 17. Development Priority

Build in this order:

1. `main.py`
2. `src/utils.py`
3. `src/analyzer.py`
4. `src/health_score.py`
5. `src/recommendations.py`
6. `src/report.py`
7. `requirements.txt`
8. `README.md`
9. GUI later

---

# 18. Final Vision

**Apoliak Vitals** should become the first module of **Apoliak Optimizer**.

First, it analyzes the PC.

Later, it can grow into:

- Safe Windows 11 optimizer
- Gaming performance tool
- Benchmark tool
- Startup cleaner
- App installer
- Game launcher

The goal is to create a trustworthy tool that clearly shows what is happening on the user's PC and recommends safe steps to improve performance.
