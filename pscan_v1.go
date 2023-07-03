//go install github.com/fatih/color@latest
//go mod init pscan
//go get github.com/fatih/color
//go run pscan_v1.go -ip 192.168.1.0/24 -ports 80,443 -onlyopen -ultrafast

package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type PortScanResult struct {
	IP     string
	Port   int
	Status string
}

func printBanner() {
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	fmt.Println("")
	fmt.Println(white("[Core |"), red("Threat]"), white(" PSCAN"))
	fmt.Println("")

}

func main() {

	printBanner()

	ipFlag := flag.String("ip", "", "Target IP address or CIDR network")
	portsFlag := flag.String("ports", "", "Comma-separated list of target ports")
	timeoutFlag := flag.Int("timeout", 5000, "Scan timeout in milliseconds")
	debugFlag := flag.Bool("debug", false, "Enable debug output")
	onlyOpenFlag := flag.Bool("onlyopen", false, "Only display open ports")
	ultraFastFlag := flag.Bool("ultrafast", false, "Enable ultrafast scan mode (timeout: 100ms)")

	flag.Parse()

	if *ipFlag == "" || *portsFlag == "" {
		fmt.Println("Please provide both the target IP address (or CIDR network) and the target ports")
		return
	}

	ipList, err := getIPList(*ipFlag)
	if err != nil {
		fmt.Printf("Invalid IP address or CIDR network: %s\n", *ipFlag)
		return
	}

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		fmt.Println("Invalid port range")
		return
	}

	timeout := time.Duration(*timeoutFlag) * time.Millisecond

	var wg sync.WaitGroup
	resultChan := make(chan PortScanResult)

	for _, ip := range ipList {
		wg.Add(1)
		go scanIP(ip, ports, timeout, resultChan, *debugFlag, *ultraFastFlag, &wg)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if !*onlyOpenFlag || result.Status == "open" {
			fmt.Printf("IP %s Port %d is %s\n", result.IP, result.Port, result.Status)
		}
	}
}

func getIPList(ipStr string) ([]string, error) {
	ipStr = strings.TrimSpace(ipStr)
	_, ipNet, err := net.ParseCIDR(ipStr)
	if err == nil {
		return getCIDRHosts(ipNet)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address or CIDR network")
	}

	return []string{ip.String()}, nil
}

func getCIDRHosts(ipNet *net.IPNet) ([]string, error) {
	var ips []string

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(portsStr string) ([]int, error) {
	portsStr = strings.TrimSpace(portsStr)
	portsArr := strings.Split(portsStr, ",")

	var ports []int

	for _, portStr := range portsArr {
		portStr = strings.TrimSpace(portStr)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("Invalid port: %s", portStr)
		}
		ports = append(ports, port)
	}

	return ports, nil
}

func scanIP(ip string, ports []int, timeout time.Duration, resultChan chan PortScanResult, debug bool, ultraFast bool, wg *sync.WaitGroup) {
	defer wg.Done()

	if debug {
		fmt.Printf("Scanning IP %s\n", ip)
	}

	for _, port := range ports {
		result := scanPort("tcp", ip, port, timeout, debug, ultraFast)
		result.IP = ip // IP-Adresse hinzufügen
		resultChan <- result
	}
}

func scanPort(protocol, ip string, port int, timeout time.Duration, debug bool, ultraFast bool) PortScanResult {
	addr := fmt.Sprintf("%s:%d", ip, port)
	result := PortScanResult{
		Port:   port,
		Status: "closed",
	}

	conn, err := net.DialTimeout(protocol, addr, timeout)
	if err != nil {
		if debug {
			fmt.Printf("Scanned IP %s Port %d\n", ip, port)
		}
		if err, ok := err.(net.Error); ok && err.Timeout() {
			result.Status = "timeout"
		}
		return result
	}

	defer conn.Close()

	result.Status = "open"
	return result
}
