package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/peterh/liner"
	"github.com/zserge/mdns"
)

func usage(exitcode int) {
	fmt.Printf("USAGE: %s <hostname> [service:port ...]\n", os.Args[0])
	os.Exit(exitcode)
}

func main() {
	if len(os.Args) < 2 {
		usage(0)
	}

	srvs := map[string]int{}

	if len(os.Args) > 2 {
		// Parse service:port pairs
		for _, s := range os.Args[2:] {
			parts := strings.Split(s, ":")
			if len(parts) != 2 {
				usage(1)
			}
			if port, err := strconv.Atoi(parts[1]); err != nil {
				usage(2)
			} else {
				srvs[parts[0]] = port
			}
		}
	}

	line := liner.NewLiner()
	defer line.Close()
	line.SetCtrlCAborts(true)

	// Start new mDNS instance
	m, err := mdns.NewMDNS(os.Args[1], srvs)
	if err != nil {
		log.Fatal(err)
	}

	// Read discovery/resolve requests in a loop until Ctrl+C is pressed
	for {
		if s, err := line.Prompt("> "); err == nil {
			line.AppendHistory(s)
			if len(s) > 0 {
				if s[0] == '_' {
					log.Println(m.Browse(s, true))
				} else {
					log.Println(m.Resolve(s))
				}
			}
		} else if err == liner.ErrPromptAborted {
			break
		} else {
			log.Fatal(err)
		}
	}

	m.Shutdown()
}
