package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Shell struct {
	ID          int
	Conn        net.Conn
	Reader      *bufio.Reader
	Writer      *bufio.Writer
	Active      bool
	Hostname    string
	RemoteAddr  string
	ConnectedAt time.Time
	ShellType   string
	mutex       sync.Mutex
	outputChan  chan string
	LastSeen    time.Time
}

type ShellManager struct {
	shells      map[int]*Shell
	nextID      int
	listeners   []net.Listener
	mutex       sync.RWMutex
	activeShell *Shell
	promptMutex sync.Mutex
}

var (
	manager *ShellManager
	colors  = struct {
		Reset   string
		Red     string
		Green   string
		Yellow  string
		Blue    string
		Magenta string
		Cyan    string
		White   string
		Bold    string
	}{
		Reset:   "\033[0m",
		Red:     "\033[31m",
		Green:   "\033[32m",
		Yellow:  "\033[33m",
		Blue:    "\033[34m",
		Magenta: "\033[35m",
		Cyan:    "\033[36m",
		White:   "\033[37m",
		Bold:    "\033[1m",
	}
)

func NewShellManager() *ShellManager {
	return &ShellManager{
		shells:    make(map[int]*Shell),
		nextID:    1,
		listeners: make([]net.Listener, 0),
	}
}

func detectShellType(conn net.Conn) string {
	buffer := make([]byte, 2048)
	conn.Write([]byte("echo $PSVersionTable\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buffer)
	conn.SetReadDeadline(time.Time{})
	if err == nil && n > 0 {
		response := strings.ToLower(string(buffer[:n]))
		if strings.Contains(response, "psversion") ||
			strings.Contains(response, "pscompatibleversions") ||
			strings.Contains(response, "ps ") ||
			strings.Contains(response, "clrversion") {
			return "powershell"
		}
		if strings.Contains(response, "$psversiontable") && !strings.Contains(response, "name") {
			return "bash"
		}
	}
	conn.Write([]byte("uname\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buffer)
	conn.SetReadDeadline(time.Time{})
	if err == nil && n > 0 {
		response := strings.ToLower(string(buffer[:n]))
		if strings.Contains(response, "linux") ||
			strings.Contains(response, "darwin") ||
			strings.Contains(response, "unix") {
			return "bash"
		}
	}
	conn.Write([]byte("echo %OS%\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buffer)
	conn.SetReadDeadline(time.Time{})
	if err == nil && n > 0 {
		response := string(buffer[:n])
		if strings.Contains(response, "Windows_NT") {
			return "cmd"
		}
	}
	return "unknown"
}

func (sm *ShellManager) StartListener(port int, useTLS bool, certFile, keyFile string) error {
	address := fmt.Sprintf("0.0.0.0:%d", port)
	var listener net.Listener
	var err error
	if useTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", address, config)
		if err != nil {
			return err
		}
		fmt.Printf("%s[+] TLS Listener started on %s%s\n", colors.Green, address, colors.Reset)
	} else {
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return err
		}
		fmt.Printf("%s[+] Listener started on %s%s\n", colors.Green, address, colors.Reset)
	}
	sm.mutex.Lock()
	sm.listeners = append(sm.listeners, listener)
	sm.mutex.Unlock()
	go sm.acceptConnectionsOnPort(listener, port)
	return nil
}

func (sm *ShellManager) StopListener(port int) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	for i, listener := range sm.listeners {
		if listener != nil {
			addr := listener.Addr().String()
			if strings.HasSuffix(addr, fmt.Sprintf(":%d", port)) {
				listener.Close()
				sm.listeners = append(sm.listeners[:i], sm.listeners[i+1:]...)
				fmt.Printf("%s[+] Stopped listener on port %d%s\n", colors.Green, port, colors.Reset)
				return nil
			}
		}
	}
	return fmt.Errorf("no listener found on port %d", port)
}

func (sm *ShellManager) ListListeners() {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	if len(sm.listeners) == 0 {
		fmt.Printf("\n%s[*] No active listeners%s\n\n", colors.Yellow, colors.Reset)
		return
	}
	fmt.Printf("\n%s%-10s %-30s%s\n", colors.Cyan, "Port", "Address", colors.Reset)
	fmt.Println(strings.Repeat("-", 45))
	for _, listener := range sm.listeners {
		if listener != nil {
			addr := listener.Addr().String()
			parts := strings.Split(addr, ":")
			port := parts[len(parts)-1]
			fmt.Printf("%-10s %-30s\n", port, addr)
		}
	}
	fmt.Println()
}

func (sm *ShellManager) acceptConnectionsOnPort(listener net.Listener, port int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				sm.printWithPrompt(fmt.Sprintf("%s[!] Error accepting connection on port %d: %v%s\n", colors.Red, port, err, colors.Reset))
			}
			return
		}
		go sm.handleNewShell(conn)
	}
}

func (sm *ShellManager) printWithPrompt(msg string) {
	sm.promptMutex.Lock()
	defer sm.promptMutex.Unlock()
	fmt.Print("\r\033[K")
	fmt.Print(msg)
	if sm.activeShell == nil {
		fmt.Print("handler> ")
	} else {
		fmt.Print("shell> ")
	}
}

func (sm *ShellManager) acceptConnections() {
}

func (sm *ShellManager) handleNewShell(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	sm.mutex.Lock()
	shell := &Shell{
		ID:          sm.nextID,
		Conn:        conn,
		Reader:      bufio.NewReader(conn),
		Writer:      bufio.NewWriter(conn),
		Active:      true,
		RemoteAddr:  conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
		outputChan:  make(chan string, 100),
	}
	sm.shells[sm.nextID] = shell
	sm.nextID++
	sm.mutex.Unlock()
	shell.ShellType = detectShellType(conn)
	time.Sleep(500 * time.Millisecond)
	tempBuf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		_, err := conn.Read(tempBuf)
		if err != nil {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	var hostnameCmd string
	switch shell.ShellType {
	case "powershell":
		hostnameCmd = "$env:COMPUTERNAME\n"
	case "cmd":
		hostnameCmd = "hostname\n"
	default:
		hostnameCmd = "hostname\n"
	}
	shell.Writer.WriteString(hostnameCmd)
	shell.Writer.Flush()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hostnameData := make([]byte, 1024)
	bytesRead, err := conn.Read(hostnameData)
	conn.SetReadDeadline(time.Time{})
	if err == nil && bytesRead > 0 {
		hostnameOutput := string(hostnameData[:bytesRead])
		lines := strings.Split(hostnameOutput, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" &&
				!strings.HasPrefix(line, "PS ") &&
				!strings.Contains(line, ">") &&
				!strings.HasPrefix(line, "$") &&
				len(line) < 50 {
				shell.Hostname = line
				break
			}
		}
		if shell.Hostname == "" {
			shell.Hostname = "unknown"
		}
	} else {
		shell.Hostname = "unknown"
	}
	notification := fmt.Sprintf("\n%s[+] New shell connected!%s\n", colors.Green, colors.Reset)
	notification += fmt.Sprintf("    ID: %s%d%s\n", colors.Cyan, shell.ID, colors.Reset)
	notification += fmt.Sprintf("    From: %s%s%s\n", colors.Yellow, shell.RemoteAddr, colors.Reset)
	notification += fmt.Sprintf("    Hostname: %s%s%s\n", colors.Magenta, shell.Hostname, colors.Reset)
	notification += fmt.Sprintf("    Shell Type: %s%s%s\n", colors.Blue, shell.ShellType, colors.Reset)
	notification += fmt.Sprintf("    Time: %s\n", shell.ConnectedAt.Format("2006-01-02 15:04:05"))
	sm.printWithPrompt(notification)
	go sm.backgroundReader(shell)
	go sm.keepAlive(shell)
}

func (sm *ShellManager) keepAlive(shell *Shell) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for shell.Active {
		<-ticker.C
		shell.mutex.Lock()
		if !shell.Active {
			shell.mutex.Unlock()
			return
		}
		shell.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		shell.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		testBuf := make([]byte, 1)
		_, err := shell.Conn.Read(testBuf[:0])
		shell.Conn.SetWriteDeadline(time.Time{})
		shell.Conn.SetReadDeadline(time.Time{})
		if err != nil && err != io.EOF {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				shell.Active = false
				shell.mutex.Unlock()
				sm.printWithPrompt(fmt.Sprintf("%s[!] Shell %d connection lost%s\n",
					colors.Red, shell.ID, colors.Reset))
				return
			}
		}
		shell.mutex.Unlock()
	}
}

func (sm *ShellManager) backgroundReader(shell *Shell) {
	defer func() {
		sm.mutex.Lock()
		shell.Active = false
		shell.Conn.Close()
		close(shell.outputChan)
		if sm.activeShell != nil && sm.activeShell.ID == shell.ID {
			sm.activeShell = nil
		}
		sm.mutex.Unlock()
		sm.printWithPrompt(fmt.Sprintf("\n%s[!] Shell %d disconnected%s\n", colors.Red, shell.ID, colors.Reset))
	}()
	buffer := make([]byte, 8192)
	for shell.Active {
		shell.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := shell.Conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			errStr := err.Error()
			if err == io.EOF ||
				strings.Contains(errStr, "use of closed network connection") ||
				strings.Contains(errStr, "forcibly closed by the remote host") ||
				strings.Contains(errStr, "connection reset by peer") ||
				strings.Contains(errStr, "broken pipe") {
				break
			}
			sm.printWithPrompt(fmt.Sprintf("%s[!] Shell %d unexpected error: %v%s\n",
				colors.Red, shell.ID, err, colors.Reset))
			break
		}
		if n > 0 {
			shell.LastSeen = time.Now()
			output := string(buffer[:n])
			shell.mutex.Lock()
			if sm.activeShell != nil && sm.activeShell.ID == shell.ID {
				fmt.Print(output)
			} else {
				select {
				case shell.outputChan <- output:
				default:
					<-shell.outputChan
					shell.outputChan <- output
				}
			}
			shell.mutex.Unlock()
		}
	}
}

func (sm *ShellManager) InteractWithShell(id int) error {
	sm.mutex.RLock()
	shell, exists := sm.shells[id]
	sm.mutex.RUnlock()
	if !exists {
		return fmt.Errorf("shell %d not found", id)
	}
	if !shell.Active {
		return fmt.Errorf("shell %d is not active", id)
	}
	sm.mutex.Lock()
	sm.activeShell = shell
	sm.mutex.Unlock()
	fmt.Printf("\n%s[*] Interacting with shell %d (%s - %s)%s\n",
		colors.Cyan, id, shell.Hostname, shell.ShellType, colors.Reset)
	fmt.Printf("%s[*] Commands: 'background'/'bg' to background, 'exit' to close shell%s\n",
		colors.Yellow, colors.Reset)
	drainOutput := true
	for drainOutput {
		select {
		case output := <-shell.outputChan:
			fmt.Print(output)
		default:
			drainOutput = false
		}
	}
	fmt.Println()
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("shell> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)
		if input == "background" || input == "bg" {
			sm.mutex.Lock()
			sm.activeShell = nil
			sm.mutex.Unlock()
			fmt.Printf("\n%s[*] Backgrounded shell %d (still running)%s\n",
				colors.Yellow, id, colors.Reset)
			return nil
		}
		if input == "exit" {
			shell.Conn.Write([]byte("exit\n"))
			time.Sleep(500 * time.Millisecond)
			shell.Conn.Close()
			shell.Active = false
			sm.mutex.Lock()
			sm.activeShell = nil
			sm.mutex.Unlock()
			fmt.Printf("\n%s[*] Closed shell %d%s\n", colors.Red, id, colors.Reset)
			return nil
		}
		if input == "" {
			continue
		}
		shell.mutex.Lock()
		_, err = shell.Conn.Write([]byte(input + "\n"))
		shell.mutex.Unlock()
		if err != nil {
			fmt.Printf("%s[!] Error sending command: %v%s\n", colors.Red, err, colors.Reset)
			shell.Active = false
			sm.mutex.Lock()
			sm.activeShell = nil
			sm.mutex.Unlock()
			return err
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func (sm *ShellManager) ListShells() {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	if len(sm.shells) == 0 {
		fmt.Printf("\n%s[*] No shells connected%s\n\n", colors.Yellow, colors.Reset)
		return
	}
	fmt.Printf("\n%s%-5s %-18s %-12s %-28s %-20s %-10s%s\n",
		colors.Cyan, "ID", "Hostname", "Type", "Remote Address", "Connected", "Status", colors.Reset)
	fmt.Println(strings.Repeat("-", 105))
	for _, shell := range sm.shells {
		status := "Active"
		statusColor := colors.Green
		if !shell.Active {
			status = "Dead"
			statusColor = colors.Red
		} else if time.Since(shell.LastSeen) > 60*time.Second {
			status = "Stale"
			statusColor = colors.Yellow
		}
		activeMarker := "  "
		if sm.activeShell != nil && sm.activeShell.ID == shell.ID {
			activeMarker = colors.Green + "► " + colors.Reset
		}
		fmt.Printf("%s%-5d %-18s %-12s %-28s %-20s %s%-10s%s\n",
			activeMarker,
			shell.ID,
			truncate(shell.Hostname, 18),
			shell.ShellType,
			truncate(shell.RemoteAddr, 28),
			shell.ConnectedAt.Format("2006-01-02 15:04:05"),
			statusColor,
			status,
			colors.Reset)
	}
	fmt.Println()
}

func (sm *ShellManager) ExecuteOnAll(command string) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	activeCount := 0
	var wg sync.WaitGroup
	for _, shell := range sm.shells {
		if shell.Active {
			activeCount++
			wg.Add(1)
			go func(s *Shell) {
				defer wg.Done()
				s.mutex.Lock()
				s.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err := s.Conn.Write([]byte(command + "\n"))
				s.Conn.SetWriteDeadline(time.Time{})
				s.mutex.Unlock()
				if err != nil {
					sm.printWithPrompt(fmt.Sprintf("%s[!] Failed to send to shell %d: %v%s\n",
						colors.Red, s.ID, err, colors.Reset))
				} else {
					sm.printWithPrompt(fmt.Sprintf("%s[+] Command sent to shell %d (%s)%s\n",
						colors.Green, s.ID, s.Hostname, colors.Reset))
				}
			}(shell)
		}
	}
	if activeCount == 0 {
		fmt.Printf("\n%s[*] No active shells to execute command%s\n", colors.Yellow, colors.Reset)
	} else {
		fmt.Printf("\n%s[*] Sending command to %d active shell(s)...%s\n", colors.Cyan, activeCount, colors.Reset)
		wg.Wait()
		fmt.Printf("%s[+] Broadcast complete%s\n\n", colors.Green, colors.Reset)
	}
}

func (sm *ShellManager) GetShellOutput(id int) error {
	sm.mutex.RLock()
	shell, exists := sm.shells[id]
	sm.mutex.RUnlock()
	if !exists {
		return fmt.Errorf("shell %d not found", id)
	}
	if !shell.Active {
		return fmt.Errorf("shell %d is not active", id)
	}
	fmt.Printf("\n%s[*] Buffered output from shell %d:%s\n", colors.Cyan, id, colors.Reset)
	fmt.Println(strings.Repeat("-", 60))
	hasOutput := false
	for {
		select {
		case output := <-shell.outputChan:
			fmt.Print(output)
			hasOutput = true
		default:
			if !hasOutput {
				fmt.Printf("%s(no buffered output)%s\n", colors.Yellow, colors.Reset)
			}
			fmt.Println(strings.Repeat("-", 60))
			return nil
		}
	}
}

func (sm *ShellManager) KillShell(id int) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	shell, exists := sm.shells[id]
	if !exists {
		return fmt.Errorf("shell %d not found", id)
	}
	shell.Conn.Close()
	shell.Active = false
	if sm.activeShell != nil && sm.activeShell.ID == id {
		sm.activeShell = nil
	}
	fmt.Printf("\n%s[+] Killed shell %d%s\n", colors.Green, id, colors.Reset)
	return nil
}

func (sm *ShellManager) ClearScreen() {
	fmt.Print("\033[2J\033[H")
	printBanner()
	fmt.Printf("%s[*] Screen cleared%s\n\n", colors.Green, colors.Reset)
}

func (sm *ShellManager) CleanupDeadShells() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	removed := 0
	for id, shell := range sm.shells {
		if !shell.Active {
			delete(sm.shells, id)
			removed++
		}
	}
	if removed > 0 {
		fmt.Printf("\n%s[+] Removed %d dead shell(s)%s\n", colors.Green, removed, colors.Reset)
	} else {
		fmt.Printf("\n%s[*] No dead shells to clean up%s\n", colors.Yellow, colors.Reset)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func printBanner() {
	banner := `
   ____        __      _____ __         ____
  / __ \____  / /_  __/ ___// /_  ___  / / /
 / / / / __ \/ / / / /\__ \/ __ \/ _ \/ / / 
/ /_/ / / / / / /_/ /___/ / / / /  __/ / /  
\____/_/ /_/_/\__, //____/_/ /_/\___/_/_/   
             /____/                         
             			By @malwarekid
    `
	fmt.Printf("%s%s%s%s\n", colors.Bold, colors.Magenta, banner, colors.Reset)
}

func printUsage() {
	usage := `
%sUsage:%s
  %s./shell-handler%s                        - Start handler (no auto-listeners)
  %s./shell-handler [port]%s                 - Start with listener on port
  %s./shell-handler [port1,port2,...]%s      - Start with multiple listeners

%sExamples:%s
  %s./shell-handler%s                        - Start handler only
  %s./shell-handler 4444%s                   - Start with listener on 4444
  %s./shell-handler 4444,8080,9001%s         - Start with multiple listeners

%sRuntime Commands:%s
  Once started, use these commands to manage listeners:
  %slisten 4444%s              - Add listener on port 4444
  %slisten 80,443,8080%s       - Add listeners on multiple ports
  %slisteners%s                - Show all active listeners
  %sstop-listen 4444%s         - Stop listener on port 4444
`
	fmt.Printf(usage,
		colors.Bold+colors.Cyan, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Bold+colors.Yellow, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Bold+colors.Cyan, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset)
}

func printHelp() {
	help := `
%sAvailable Commands:%s
  %slisten <port>%s           - listen on ports (443 or 443, 4443)
  %sstop-listen <port>%s      - stop listener on ports (443 or 443, 4443)
  %slist%s / %sls%s               - List all shells with status
  %sinteract <id>%s / %si <id>%s  - Interact with a specific shell
  %soutput <id>%s / %so <id>%s    - View buffered output from a shell
  %skill <id>%s               - Kill a specific shell connection
  %sexec-all <command>%s      - Execute command on all active shells
  %scleanup%s                 - Remove dead shells from list
  %shelp%s / %s?%s                - Show this help message
  %sexit%s / %squit%s             - Exit handler (closes all shells)

%sWhen interacting with a shell:%s
  %sbackground%s / %sbg%s         - Return to handler (shell stays alive)
  %sexit%s                    - Close the current shell
`
	fmt.Printf(help,
		colors.Bold+colors.Cyan, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Bold+colors.Yellow, colors.Reset,
		colors.Green, colors.Reset, colors.Green, colors.Reset,
		colors.Green, colors.Reset)
}

func main() {
	printBanner()
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printUsage()
		os.Exit(0)
	}
	manager = NewShellManager()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n\n%s[*] Shutting down gracefully...%s\n", colors.Yellow, colors.Reset)
		manager.mutex.Lock()
		for _, listener := range manager.listeners {
			if listener != nil {
				listener.Close()
			}
		}
		manager.mutex.Unlock()
		os.Exit(0)
	}()
	if len(os.Args) > 1 {
		var ports []int
		if strings.Contains(os.Args[1], ",") {
			portStrings := strings.Split(os.Args[1], ",")
			for _, ps := range portStrings {
				ps = strings.TrimSpace(ps)
				if p, err := strconv.Atoi(ps); err == nil {
					ports = append(ports, p)
				} else {
					log.Fatalf("%s[!] Invalid port: %s%s\n", colors.Red, ps, colors.Reset)
				}
			}
		} else {
			if p, err := strconv.Atoi(os.Args[1]); err == nil {
				ports = []int{p}
			} else {
				log.Fatalf("%s[!] Invalid port: %s%s\n", colors.Red, os.Args[1], colors.Reset)
			}
		}
		for _, port := range ports {
			err := manager.StartListener(port, false, "", "")
			if err != nil {
				log.Fatalf("%s[!] Failed to start listener on port %d: %v%s\n", colors.Red, port, err, colors.Reset)
			}
		}
		if len(ports) > 1 {
			fmt.Printf("%s[*] Started %d listeners%s\n", colors.Green, len(ports), colors.Reset)
		}
	}
	fmt.Printf("%s[*] Type 'help' for available commands%s\n\n", colors.Cyan, colors.Reset)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("handler> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				break
			}
			log.Printf("%s[!] Input error: %v%s\n", colors.Red, err, colors.Reset)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		parts := strings.SplitN(input, " ", 2)
		command := parts[0]
		var args string
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
		}
		switch command {
		case "help", "?":
			printHelp()
		case "list", "ls":
			manager.ListShells()
		case "listeners":
			manager.ListListeners()
		case "listen":
			if args == "" {
				fmt.Printf("%s[!] Usage: listen <port> or listen <port1,port2,...>%s\n", colors.Red, colors.Reset)
				fmt.Printf("%s    Examples: listen 4444 or listen 4444,8080 or listen 80, 443, 8080%s\n", colors.Yellow, colors.Reset)
				continue
			}
			cleanArgs := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, args)
			if cleanArgs == "" {
				fmt.Printf("%s[!] No ports specified%s\n", colors.Red, colors.Reset)
				continue
			}
			var ports []int
			portParts := strings.Split(cleanArgs, ",")
			for _, portStr := range portParts {
				if portStr == "" {
					continue
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					fmt.Printf("%s[!] Invalid port: '%s'%s\n", colors.Red, portStr, colors.Reset)
					continue
				}
				if port < 1 || port > 65535 {
					fmt.Printf("%s[!] Port out of range (1-65535): %d%s\n", colors.Red, port, colors.Reset)
					continue
				}
				ports = append(ports, port)
			}
			if len(ports) == 0 {
				fmt.Printf("%s[!] No valid ports to start%s\n", colors.Red, colors.Reset)
				continue
			}
			successCount := 0
			failCount := 0
			for _, port := range ports {
				err := manager.StartListener(port, false, "", "")
				if err != nil {
					fmt.Printf("%s[!] Failed to start listener on port %d: %v%s\n", colors.Red, port, err, colors.Reset)
					failCount++
				} else {
					successCount++
				}
			}
			if successCount > 1 {
				fmt.Printf("%s[+] Successfully started %d listener(s)%s\n", colors.Green, successCount, colors.Reset)
			}
			if failCount > 0 {
				fmt.Printf("%s[!] Failed to start %d listener(s)%s\n", colors.Red, failCount, colors.Reset)
			}
		case "stop-listen":
			if args == "" {
				fmt.Printf("%s[!] Usage: stop-listen <port> or stop-listen <port1,port2,...>%s\n", colors.Red, colors.Reset)
				continue
			}
			cleanArgs := strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, args)
			var ports []int
			portParts := strings.Split(cleanArgs, ",")
			for _, portStr := range portParts {
				if portStr == "" {
					continue
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					fmt.Printf("%s[!] Invalid port: '%s'%s\n", colors.Red, portStr, colors.Reset)
					continue
				}
				ports = append(ports, port)
			}
			successCount := 0
			failCount := 0
			for _, port := range ports {
				if err := manager.StopListener(port); err != nil {
					fmt.Printf("%s[!] %v%s\n", colors.Red, err, colors.Reset)
					failCount++
				} else {
					successCount++
				}
			}
			if successCount > 0 {
				fmt.Printf("%s[+] Successfully stopped %d listener(s)%s\n", colors.Green, successCount, colors.Reset)
			}
		case "interact", "i":
			if args == "" {
				fmt.Printf("%s[!] Usage: interact <shell_id>%s\n", colors.Red, colors.Reset)
				continue
			}
			id, err := strconv.Atoi(args)
			if err != nil {
				fmt.Printf("%s[!] Invalid shell ID%s\n", colors.Red, colors.Reset)
				continue
			}
			manager.InteractWithShell(id)
		case "output", "o":
			if args == "" {
				fmt.Printf("%s[!] Usage: output <shell_id>%s\n", colors.Red, colors.Reset)
				continue
			}
			id, err := strconv.Atoi(args)
			if err != nil {
				fmt.Printf("%s[!] Invalid shell ID%s\n", colors.Red, colors.Reset)
				continue
			}
			manager.GetShellOutput(id)
		case "kill":
			if args == "" {
				fmt.Printf("%s[!] Usage: kill <shell_id>%s\n", colors.Red, colors.Reset)
				continue
			}
			id, err := strconv.Atoi(args)
			if err != nil {
				fmt.Printf("%s[!] Invalid shell ID%s\n", colors.Red, colors.Reset)
				continue
			}
			if err := manager.KillShell(id); err != nil {
				fmt.Printf("%s[!] %v%s\n", colors.Red, err, colors.Reset)
			}
		case "exec-all":
			if args == "" {
				fmt.Printf("%s[!] Usage: exec-all <command>%s\n", colors.Red, colors.Reset)
				continue
			}
			manager.ExecuteOnAll(args)
		case "cleanup":
			manager.CleanupDeadShells()
		case "clear", "cls":
			manager.ClearScreen()
		case "exit", "quit":
			fmt.Printf("\n%s[*] Shutting down handler...%s\n", colors.Red, colors.Reset)
			manager.mutex.Lock()
			for _, listener := range manager.listeners {
				if listener != nil {
					listener.Close()
				}
			}
			manager.mutex.Unlock()
			os.Exit(0)
		default:
			fmt.Printf("%s[!] Unknown command: '%s'. Type 'help' for available commands%s\n",
				colors.Red, command, colors.Reset)
		}
	}
}