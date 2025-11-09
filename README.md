# OnlyShell

## Overview
**OnlyShell** is a powerful Go-based reverse shell handler that allows you to manage multiple reverse shell connections simultaneously. It provides an intuitive command-line interface with features like shell type detection, background shell management, command broadcasting, and real-time interaction with connected shells. This tool is designed for penetration testers and security researchers who need efficient multi-shell management.

## Features
- **Multi-Shell Management:** Handle unlimited simultaneous reverse shell connections
- **Shell Type Detection:** Automatically detects bash, PowerShell, cmd, and other shell types
- **Multiple Listeners:** Start listeners on multiple ports simultaneously
- **Background Shell Support:** Background shells and return to them without losing the connection
- **Command Broadcasting:** Execute commands across all active shells at once
- **Silent Keepalive:** Non-intrusive connection monitoring without interfering with shell sessions
- **Status Tracking:** Monitor shell status (Active, Stale, Dead) and last seen timestamps
- **TLS Support:** Optional encrypted connections for secure communications
- **Session Management:** View buffered output from backgrounded shells
- **Color-Coded Output:** Easy-to-read colored terminal output for better visibility

---

## Download Pre-Build from Release - [OnlyShell](https://github.com/malwarekid/OnlyShell/releases)

## Installation

### Prerequisites
- Go 1.16 or higher

### Build from Source
1. **Clone the Repository:**
```bash
git clone https://github.com/malwarekid/OnlyShell.git && cd OnlyShell
```

2. **Cross-Compiling**

You can build binaries for multiple platforms:

**Linux (from any OS):**

```bash
GOOS=linux GOARCH=amd64 go build -o OnlyShell main.go
```

**Windows (from Linux/macOS):**

```bash
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o OnlyShell.exe main.go
```

**macOS:** (Not Tested)

```bash
GOOS=darwin GOARCH=amd64 go build -o OnlyShell main.go
```

## How to Use

<img width="863" height="660" alt="onlyshell" src="https://github.com/user-attachments/assets/aab2440e-6836-4174-b96b-b9d7b30d6e6f" />

### Starting the Handler

**Start without listeners:**
```bash
OnlyShell.exe
```

**Start with a single listener:**
```bash
OnlyShell.exe 4444
```

**Start with multiple listeners:**
```bash
OnlyShell.exe 4444,8080,9001
```

## Usage Example

```bash
# Start the handler with listener on port 4444
OnlyShell.exe 4444

[+] Listener started on 0.0.0.0:4444
[*] Type 'help' for available commands

# Wait for incoming connections
[+] New shell connected!
    ID: 1
    From: 192.168.1.100:54321
    Hostname: target-machine
    Shell Type: bash
    Time: 2024-11-04 15:30:45

# List all shells
handler> list

ID    Hostname           Type         Remote Address               Connected             Status    
---------------------------------------------------------------------------------------------------------
► 1   target-pc          powershell   192.168.1.100:54321          2024-11-04 15:30:45   Active    
  2   ubuntu-server      bash         192.168.1.101:54322          2024-11-04 15:31:12   Active    

# Interact with shell 1
handler> interact 1

[*] Interacting with shell 1 (target-pc - powershell)
[*] Commands: 'background'/'bg' to background, 'exit' to close shell

shell> whoami
target-pc\admin

shell> pwd
C:\Users\admin

# Background the shell
shell> background

[*] Backgrounded shell 1 (still running)

# Execute command on all active shells
handler> exec-all whoami

[*] Sending command to 2 active shell(s)...
[+] Command sent to shell 1 (target-pc)
[+] Command sent to shell 2 (ubuntu-server)
[+] Broadcast complete

# Add more listeners at runtime
handler> listen 9001,9002

[+] Listener started on 0.0.0.0:9001
[+] Listener started on 0.0.0.0:9002
[+] Successfully started 2 listener(s)

# View all active listeners
handler> listeners

Port       Address                       
---------------------------------------------
4444       0.0.0.0:4444                  
9001       0.0.0.0:9001                  
9002       0.0.0.0:9002                  

# Clean up dead shells
handler> cleanup

[+] Removed 1 dead shell(s)
```

## Shell Status Indicators

- **Active** (Green) - Shell is connected and responsive
- **Stale** (Yellow) - No activity for more than 60 seconds
- **Dead** (Red) - Connection lost or terminated
- **>** (Green Arrow) - Currently active/interacting shell

## Requirements
- Go 1.16+
- Network connectivity
- Appropriate permissions for binding to ports (low ports require root/admin)

## Security Considerations

⚠️ **Warning:** This tool is intended strictly for **authorized use in internal environments**.
The author assumes **no liability** for misuse or damages caused by this software.

- Use TLS encryption for sensitive operations
- Only use on networks and systems you are authorized to test
- Be aware of logs and detection mechanisms
- Follow responsible disclosure practices

## Contributors
- [Malwarekid](https://github.com/malwarekid)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Notes

Feel free to contribute, report issues, or provide feedback. Don't forget to follow me on [Instagram](https://www.instagram.com/malwarekid/) and [GitHub](https://github.com/malwarekid). Happy Pentesting! 🔒

