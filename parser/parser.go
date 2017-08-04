package parser

import (
	"flag"
	"fmt"
	"os"
)

// Function usage()
// Display the usage of ORFinder
func usage() {
	fmt.Println("Usage: ./ORfinder -c [en | ru | fr | ...]")
	flag.PrintDefaults()
	os.Exit(1)
}

// Function Parse() string
// Parse the arguments
// Return the given country code
func Parse() string {
	var country string

	flag.StringVar(&country, "c", "ru", "Country code. List available at https://en.wikipedia.org/wiki/ISO_3166-1")

	flag.Parse()

	if flag.NFlag() == 0 {
		usage()
	}

	return country
}
