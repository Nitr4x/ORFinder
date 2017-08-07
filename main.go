package main

import (
	"fmt"
	"orfinder/engine/loader"
	"orfinder/engine/scanner"
	"orfinder/parser"
	"sync"
)

// Function Welcome()
// Display ascii art
func welcome() {
	fmt.Println(`
        ██████╗ ██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
       ██╔═══██╗██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
       ██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
       ██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
       ╚██████╔╝██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
        ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

        ORFinder allows scanning the internet to find SMTP services
        vulnerable to open relay attack.
        Maintained by Nitrax <nitrax@lokisec.fr>
    `)
}

// Function main()
// ORFinder entry point
func main() {
	var wg sync.WaitGroup

	welcome()

	country := parser.Parse()
	IPs := loader.Load(country)
	tasks := make(chan string)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			for task := range tasks {
				scanner.Scan(task)
			}
			wg.Done()
		}()
	}

	for i := len(IPs) - 1; i >= 0; i-- {
		tasks <- IPs[i]
	}

	close(tasks)

	wg.Wait()
}
