package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosuri/uilive"
)

var address string
var port int
var portRange string
var portCommon bool

var startPort int
var endPort int

var method string

type ports struct {
	port   int
	output string
}

var outputPorts []ports

var commonPorts []int

func init() {
	flag.StringVar(&address, "d", "", "Enter the domainname you want to sniff")
	flag.StringVar(&address, "ip", "", "Enter the ip address you want to sniff")
	flag.IntVar(&port, "p", 0, "Check one port")
	flag.StringVar(&portRange, "pr", "", "Check a port range. Define '[start]-[end]'")
	flag.BoolVar(&portCommon, "pc", false, "Check the common ports")

	flag.Parse()

	if address == "" {
		log.Println("We need an address to sniff")
		fmt.Println("Usage of 'Portsniffer':")
		flag.PrintDefaults()
		os.Exit(111)
	}

	if !portCommon {
		if port == 0 && portRange == "" {
			port = 443
			method = "port"
		} else if port != 0 {
			method = "port"
		} else if portRange != "" {
			ports := strings.Split(portRange, "-")

			if len(ports) != 2 {
				log.Fatal("Separate the start port and the end port with a '-'. Example: 80-443")
			}

			F_startPort, _ := strconv.Atoi(ports[0])
			F_endPort, _ := strconv.Atoi(ports[1])

			startPort = F_startPort
			endPort = F_endPort
			method = "range"
		}
	} else {
		method = "common"
	}

	commonPorts = append(commonPorts, 1, 7, 20, 21, 22, 23, 25, 42, 43, 53, 69, 79, 80, 88, 106, 110, 111, 113, 115, 119, 123, 135, 137, 138, 139, 143, 161, 177, 194, 311, 379, 389, 427, 443, 445, 464, 465, 497, 514, 515, 532, 548, 554, 587, 600, 625, 631, 636, 660, 687, 749, 985, 993, 995, 1080, 1085, 1194, 1099, 1220, 1433, 1434, 1521, 1522, 1525, 1529, 1640, 1649, 1723, 1990, 1998, 2049, 2195, 2196, 2336, 3004, 3031, 3128, 3283, 3306, 3389, 3689, 4111, 4488, 5000, 5001, 5003, 5009, 5010, 5060, 5100, 5190, 5200, 5222, 5223, 5269, 5298, 5432, 5500, 5632, 5800, 5900, 5988, 6000, 7070, 7777, 8005, 8008, 8043, 8080, 8085, 8086, 8087, 8088, 8089, 8096, 8170, 8171, 8175, 8200, 8443, 8800, 8821, 8826, 8843, 8880, 8891, 9006, 9100, 10000, 10001, 10002, 10010, 20005, )
}

func main() {
	switch method {
	case "port":
		fmt.Println("Sniffing port", port, "on", address)
		outputPorts = append(outputPorts, ports{
			port:   port,
			output: sniff(address, port),
		})
		// fmt.Printf("%v: %v\n", port, check[1])
	case "range":
		var wg sync.WaitGroup
		fmt.Println("Sniffing an range of ports")

		writer := uilive.New()
		writer.Start()
		totalPorts := (endPort - startPort) + 1
		execution := []int{}

		// fmt.Fprintf(writer, "Sniffing ports: %d of the %d sniffed\n", 0, totalPorts)


		for i := startPort; i < endPort+1; i++ {
			execution = append(execution, i)

			if len(execution) >= 10 || i == endPort {
				for _, c := range execution {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						sniffOutput := sniff(address, i)

						outputPorts = append(outputPorts, ports{
							port:   i,
							output: sniffOutput,
						})
					}(c)
				}

				execution = []int{}

				currentPort := i - startPort

				fmt.Fprintf(writer, "Sniffing ports: %d of the %d sniffed\n", currentPort, totalPorts)
			}
			wg.Wait()
		}

		fmt.Fprintln(writer, "Finished sniffing ports ;^)")
		writer.Stop()

	case "common":
		var wg sync.WaitGroup
		fmt.Println("Sniffing common ports")

		writer := uilive.New()
		writer.Start()
		execution := []int{}

		// fmt.Fprintf(writer, "Sniffing ports: %d of the %d sniffed\n", 0, totalPorts)

		for i := 0; i < len(commonPorts); i++ {
			execution = append(execution, commonPorts[i])

			if len(execution) >= 10 || i == len(commonPorts)-1 {
				for _, c := range execution {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						sniffOutput := sniff(address, i)

						outputPorts = append(outputPorts, ports{
							port:   i,
							output: sniffOutput,
						})
					}(c)
				}

				execution = []int{}

				portScanned := len(commonPorts) - i

				fmt.Fprintf(writer, "Sniffing ports: %d of the %d sniffed\n", i, len(commonPorts))
			}
			wg.Wait()
		}

		fmt.Fprintln(writer, "Finished sniffing ports ;^)")
		writer.Stop()
	}

	sort.Slice(outputPorts[:], func(i, j int) bool {
		return outputPorts[i].port < outputPorts[j].port
	})

	i := 0
	startPlace := 0
	startBool := true

	for _, c := range outputPorts {
		if startBool {
			startPlace = c.port
			startBool = !startBool
		}

		if len(outputPorts) > 1 {
			if i >= 1 {
				// log.Println("i:", i, " c:", c)
				if outputPorts[i-1].output != c.output {
					if startPlace == outputPorts[i-1].port {
						fmt.Printf("%v: %v\n", outputPorts[i-1].port, outputPorts[i-1].output)
					} else {
						fmt.Printf("%v - %v: %v\n", startPlace, c.port-1, outputPorts[i-1].output)
					}

					startPlace = c.port
				}
			}

			i++

			if len(outputPorts) == i {
				if startPlace == c.port {
					fmt.Printf("%v: %v\n", c.port, c.output)
				} else {
					fmt.Printf("%v - %v: %v\n", startPlace, c.port, c.output)
				}
			}
		} else {
			fmt.Printf("%v: %v\n", c.port, c.output)
		}
	}
}

func sniff(address string, port int) string {
	F_port := strconv.Itoa(port)

	_, c := net.DialTimeout("tcp", address+":"+F_port, time.Second)

	if c == nil {
		return "Open"
	}

	// log.Println(c)

	err := strings.Split(c.Error(), ": ")

	errCode := len(err) - 1

	// fmt.Println(err[errCode])

	switch err[errCode] {
	case "i/o timeout":
		return "Blocked"
	case "connection refused":
		return "Closed"
	default:
		return "Unknown"
	}
}
