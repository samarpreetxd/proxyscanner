package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
)

// Config holds CLI/configuration parameters
type Config struct {
    Timeout         int    `json:"timeout"`
    Workers         int    `json:"workers"`
    RefreshInterval int    `json:"refresh_interval"`
    OutputDir       string `json:"output_dir"`
    LogLevel        string `json:"log_level"`
}

func main() {
    // --- CLI Flags ---
    timeout := flag.Int("timeout", 3, "connection timeout (seconds)")
    workers := flag.Int("workers", runtime.NumCPU()*2, "number of concurrent workers")
    refreshInterval := flag.Int("refresh-interval", 60, "interval to re-test proxies (minutes)")
    outputDir := flag.String("output-dir", ".", "directory for output file(s)")
    logLevel := flag.String("log-level", "info", "log level (info|debug|quiet)")
    configFile := flag.String("config", "", "JSON config file (optional)")
    flag.Parse()

    // --- Load Config from File if Provided ---
    if *configFile != "" {
        file, err := os.Open(*configFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error opening config file: %v\n", err)
            os.Exit(1)
        }
        defer file.Close()
        dec := json.NewDecoder(file)
        cfg := Config{}
        if err := dec.Decode(&cfg); err != nil {
            fmt.Fprintf(os.Stderr, "Invalid JSON config: %v\n", err)
            os.Exit(1)
        }
        if *timeout == 3 && cfg.Timeout != 0 {
            *timeout = cfg.Timeout
        }
        if *workers == runtime.NumCPU()*2 && cfg.Workers != 0 {
            *workers = cfg.Workers
        }
        if *refreshInterval == 60 && cfg.RefreshInterval != 0 {
            *refreshInterval = cfg.RefreshInterval
        }
        if *outputDir == "." && cfg.OutputDir != "" {
            *outputDir = cfg.OutputDir
        }
        if *logLevel == "info" && cfg.LogLevel != "" {
            *logLevel = cfg.LogLevel
        }
    }

    // --- Read CIDRs from Cidr.txt ---
    cidrList, err := readLines("Cidr.txt")
    if err != nil {
        log.Fatalf("Error reading Cidr.txt: %v", err)
    }

    // --- Read Ports from Ports.txt ---
    portRanges, err := readLines("Ports.txt")
    if err != nil {
        log.Fatalf("Error reading Ports.txt: %v", err)
    }

    // --- Expand all CIDRs to IPs ---
    var allIPs []string
    for _, cidr := range cidrList {
        _, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
        if err != nil {
            log.Printf("Skipping invalid CIDR %s: %v", cidr, err)
            continue
        }
        ips := expandCIDR(ipnet)
        allIPs = append(allIPs, ips...)
    }
    if len(allIPs) == 0 {
        log.Fatal("No valid IPs found from CIDRs")
    }

    // --- Parse all port ranges ---
    var portsToScan []int
    for _, pr := range portRanges {
        pr = strings.TrimSpace(pr)
        if strings.Contains(pr, "-") {
            startPort, endPort, err := parsePortRange(pr)
            if err != nil {
                log.Printf("Skipping invalid port range %s: %v", pr, err)
                continue
            }
            for p := startPort; p <= endPort; p++ {
                portsToScan = append(portsToScan, p)
            }
        } else {
            p, err := strconv.Atoi(pr)
            if err != nil {
                log.Printf("Skipping invalid port %s: %v", pr, err)
                continue
            }
            portsToScan = append(portsToScan, p)
        }
    }
    if len(portsToScan) == 0 {
        log.Fatal("No valid ports found in Ports.txt")
    }

    // --- Prepare output file ---
    os.MkdirAll(*outputDir, os.ModePerm)
    outPath := *outputDir + string(os.PathSeparator) + "proxies.txt"
    outFile, err := os.Create(outPath)
    if err != nil {
        log.Fatalf("Cannot create output file: %v", err)
    }
    defer outFile.Close()

    foundChan := make(chan string, 100)
    var writerWg sync.WaitGroup
    writerWg.Add(1)
    go func() {
        defer writerWg.Done()
        writer := bufio.NewWriter(outFile)
        for entry := range foundChan {
            writer.WriteString(entry + "\n")
            writer.Flush()
        }
    }()

    // --- Scanning ---
    type Task struct{ IP string; Port int }
    tasks := make(chan Task, *workers*2)
    var scanWg sync.WaitGroup

    for i := 0; i < *workers; i++ {
        scanWg.Add(1)
        go func() {
            defer scanWg.Done()
            for task := range tasks {
                address := fmt.Sprintf("%s:%d", task.IP, task.Port)

                logPrint("debug", *logLevel, "[*] Testing %s\n", address)

                if checkHTTP(address, *timeout) {
                    logPrint("info", *logLevel, "[+] %s → HTTP\n", address)
                    foundChan <- fmt.Sprintf("%s - HTTP", address)
                    continue
                }
                if checkSOCKS4(address, *timeout) {
                    logPrint("info", *logLevel, "[+] %s → SOCKS4\n", address)
                    foundChan <- fmt.Sprintf("%s - SOCKS4", address)
                    continue
                }
                if checkSOCKS5(address, *timeout) {
                    logPrint("info", *logLevel, "[+] %s → SOCKS5\n", address)
                    foundChan <- fmt.Sprintf("%s - SOCKS5", address)
                    continue
                }
            }
        }()
    }

    // Send all tasks
    for _, ip := range allIPs {
        for _, port := range portsToScan {
            tasks <- Task{IP: ip, Port: port}
        }
    }
    close(tasks)
    scanWg.Wait()
    close(foundChan)
    writerWg.Wait()
}

// readLines reads all lines from a text file into a string slice
func readLines(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            lines = append(lines, line)
        }
    }
    return lines, scanner.Err()
}

// --- Logging helper ---
func logPrint(level string, currentLevel string, format string, args ...interface{}) {
    levels := map[string]int{"quiet": 0, "info": 1, "debug": 2}
    if levels[currentLevel] >= levels[level] {
        fmt.Printf(format, args...)
    }
}

// --- Port Range Parser ---
func parsePortRange(s string) (int, int, error) {
    parts := strings.Split(s, "-")
    if len(parts) != 2 {
        return 0, 0, fmt.Errorf("range must be start-end")
    }
    start, err := strconv.Atoi(parts[0])
    if err != nil {
        return 0, 0, err
    }
    end, err := strconv.Atoi(parts[1])
    if err != nil {
        return 0, 0, err
    }
    return start, end, nil
}

// --- CIDR Expander ---
func expandCIDR(ipnet *net.IPNet) []string {
    var list []string
    for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIP(ip) {
        list = append(list, ip.String())
    }
    return list
}

func nextIP(ip net.IP) net.IP {
    ip = ip.To4()
    for i := len(ip) - 1; i >= 0; i-- {
        ip[i]++
        if ip[i] != 0 {
            break
        }
    }
    return ip
}

// --- Proxy Checks ---

// HTTP: request to www.google.com
func checkHTTP(address string, timeoutSec int) bool {
    conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutSec)*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    request := "GET http://www.google.com/ HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
    conn.Write([]byte(request))
    conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil || n <= 0 {
        return false
    }
    resp := string(buf[:n])
    return strings.Contains(resp, "HTTP/1.1") || strings.Contains(resp, "HTTP/1.0")
}

// SOCKS4: connect to Google IP 142.250.74.68:80
func checkSOCKS4(address string, timeoutSec int) bool {
    conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutSec)*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    destIP := net.ParseIP("142.250.74.68").To4() // Google
    if destIP == nil {
        return false
    }
    port := 80
    req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xFF)}
    req = append(req, destIP...)
    req = append(req, 0x00)
    conn.Write(req)
    conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
    reply := make([]byte, 8)
    n, err := conn.Read(reply)
    if err != nil || n < 2 {
        return false
    }
    return reply[1] == 0x5A
}

// SOCKS5: connect to www.google.com:80 via hostname
func checkSOCKS5(address string, timeoutSec int) bool {
    conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutSec)*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    conn.Write([]byte{0x05, 0x01, 0x00})
    conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
    resp := make([]byte, 2)
    if _, err := conn.Read(resp); err != nil || resp[1] != 0x00 {
        return false
    }
    dest := "www.google.com"
    port := 80
    req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dest))}
    req = append(req, []byte(dest)...)
    req = append(req, byte(port>>8), byte(port&0xFF))
    conn.Write(req)
    conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
    resp = make([]byte, 10)
    n, err := conn.Read(resp)
    if err != nil || n < 2 {
        return false
    }
    return resp[1] == 0x00
}
