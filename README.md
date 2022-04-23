# Malware-Detector-Repeat

## Abstract
Information security has become ubiquitous in this era. in this project we try to demonstrate a simple anti-malware prototype consisting of a system mointer that mointers the system and warns the user in case of any problems like fork bomb or memory bad behavior, quarantine, kills, and removes the malware. 

## System Components
### System Monitor
The main component of the system. presents the user with a summary of system metrics, then ask the user if he wants more info about:
- CPU
- RAM
- Disk
- Netwrok
- fresh new summary

or do a scan or exit. while the program is running a thread running in the background notifies the user about any warnings or potential threats to the system and runs a scan automatically in these case.

### Processes Scanner
it is python script that detects the fork bomb malware which overload the os and make it out of control and capable of killing this parent process .

### Memory Scanner
memory eater  is malware that allocates and deallocates the heap in the RAM by variant size ,so this scanner can detect this bad program and finally kill or stop this process

## Getting started
To get started: 
### Installation
The development environment is ubuntu linux and can be extended to other environments.
The script is written in python 3 , follow the installation steps: 
- `sudo apt-get update`
- `sudo apt-get install -y python3-pip`
- `pip install psutil`

we use the C programming language to build the malicious program, and we used gcc for compilation `sudo apt-get install gcc`
### Usage
- download the files
- open a terminal
- compile 
- run 
- open another terminal and run `python3 main.py`

### Sample Output
 ![launching memory eater](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/1.PNG?raw=true)
 
 ![launching manager](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/2.PNG?raw=true)
 
 ![launching memory eater](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/3.PNG?raw=true)
 
 ![launching memory eater](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/4.PNG?raw=true)
  
 ![launching memory eater](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/5.PNG?raw=true)
   
 ![launching memory eater](https://github.com/KareimGazer/Malware-Detector-Repeat/blob/main/screenshots/6.PNG?raw=true)

## The Nitty-Gritty Details
The program is divided into

## Folder Structure

Refer to the following table for information about important directories and files in this repository.

```
Malware-Detector-Repeat
├── screenshots         to be added ...
├── README.md           main documentation.
├── SysMonitor.py       used to identify and stop the program.
├── Scan.py             the scanner part.
└── main.py             driver code
```
