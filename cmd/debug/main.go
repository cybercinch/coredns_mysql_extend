package main

import (
	"flag"
	"fmt"
	"os"

	mysql "github.com/cybercinch/coredns_mysql_extend"
)

func main() {
	var dsn = flag.String("dsn", "", "MySQL DSN (username:password@tcp(host:port)/database)")
	var zone = flag.String("zone", "", "Zone name to debug (e.g., 'guise.net.nz.')")
	flag.Parse()

	if *dsn == "" {
		fmt.Println("Usage: go run cmd/debug/main.go -dsn 'user:pass@tcp(host:port)/db' -zone 'example.com.'")
		fmt.Println("Example: go run cmd/debug/main.go -dsn 'coredns:password@tcp(localhost:3306)/coredns' -zone 'guise.net.nz.'")
		os.Exit(1)
	}

	if *zone == "" {
		fmt.Println("Please specify a zone name with -zone")
		os.Exit(1)
	}

	mysql.DebugAuthorityIssue(*dsn, *zone)
}