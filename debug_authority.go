package coredns_mysql_extend

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

// DebugAuthorityIssue helps diagnose why authority records aren't showing up
func DebugAuthorityIssue(dsn, zoneName string) {
	fmt.Printf("=== Debugging Authority Records for zone: %s ===\n", zoneName)
	
	// Connect to database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	
	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("✓ Database connection successful")
	
	// 1. Check if the zone exists
	var zoneID int
	var foundZoneName string
	err = db.QueryRow("SELECT id, zone_name FROM zones WHERE zone_name = ?", zoneName).Scan(&zoneID, &foundZoneName)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ Zone '%s' not found in zones table\n", zoneName)
			// List existing zones
			rows, err := db.Query("SELECT id, zone_name FROM zones ORDER BY zone_name")
			if err == nil {
				fmt.Println("\nExisting zones:")
				for rows.Next() {
					var id int
					var name string
					if rows.Scan(&id, &name) == nil {
						fmt.Printf("  - ID: %d, Name: %s\n", id, name)
					}
				}
				rows.Close()
			}
			return
		}
		log.Fatalf("Failed to query zones table: %v", err)
	}
	fmt.Printf("✓ Zone found: ID=%d, Name='%s'\n", zoneID, foundZoneName)
	
	// 2. Check for NS records in the zone
	fmt.Printf("\nChecking for NS records in zone %d...\n", zoneID)
	rows, err := db.Query("SELECT id, zone_id, hostname, type, data, ttl, online FROM records WHERE zone_id = ? AND type = 'NS'", zoneID)
	if err != nil {
		log.Fatalf("Failed to query records table: %v", err)
	}
	defer rows.Close()
	
	nsCount := 0
	fmt.Println("NS records found:")
	for rows.Next() {
		var id, zoneIdField, ttl, online int
		var hostname, recordType, data string
		if err := rows.Scan(&id, &zoneIdField, &hostname, &recordType, &data, &ttl, &online); err != nil {
			log.Printf("Failed to scan record: %v", err)
			continue
		}
		nsCount++
		fmt.Printf("  - ID: %d, hostname: '%s', data: '%s', ttl: %d, online: %d\n", 
			id, hostname, data, ttl, online)
	}
	
	if nsCount == 0 {
		fmt.Printf("❌ No NS records found for zone ID %d\n", zoneID)
		fmt.Println("\nTo fix this, you need to add NS records. Example SQL:")
		fmt.Printf("INSERT INTO records (zone_id, hostname, type, data, ttl, online) VALUES\n")
		fmt.Printf("  (%d, '@', 'NS', 'ns1.%s', 3600, 1),\n", zoneID, zoneName)
		fmt.Printf("  (%d, '@', 'NS', 'ns2.%s', 3600, 1);\n", zoneID, zoneName)
	} else {
		fmt.Printf("✓ Found %d NS records for zone %d\n", nsCount, zoneID)
		
		// Check if any are online and use '@' hostname
		onlineAtApex := 0
		err = db.QueryRow("SELECT COUNT(*) FROM records WHERE zone_id = ? AND type = 'NS' AND hostname = '@' AND online != 0", zoneID).Scan(&onlineAtApex)
		if err == nil {
			if onlineAtApex > 0 {
				fmt.Printf("✓ Found %d online NS records with hostname='@' (apex records)\n", onlineAtApex)
			} else {
				fmt.Printf("❌ No online NS records with hostname='@' found\n")
				fmt.Println("Authority records need hostname='@' for zone apex records")
			}
		}
	}
	
	// 3. Test the exact query that getAuthorityRecords uses
	fmt.Printf("\nTesting exact query used by getAuthorityRecords...\n")
	querySQL := "SELECT id, zone_id, hostname, type, data, ttl FROM records WHERE online!=0 and zone_id=? and hostname=? and type=?"
	fmt.Printf("Query: %s\n", querySQL)
	fmt.Printf("Parameters: zone_id=%d, hostname='@', type='NS'\n", zoneID)
	
	rows2, err := db.Query(querySQL, zoneID, "@", "NS")
	if err != nil {
		log.Fatalf("Failed to execute authority query: %v", err)
	}
	defer rows2.Close()
	
	authCount := 0
	for rows2.Next() {
		var id, zoneIdField, ttl int
		var hostname, recordType, data string
		if err := rows2.Scan(&id, &zoneIdField, &hostname, &recordType, &data, &ttl); err != nil {
			log.Printf("Failed to scan authority record: %v", err)
			continue
		}
		authCount++
		rrString := fmt.Sprintf("%s %d IN NS %s", zoneName, ttl, data)
		fmt.Printf("  - Authority record: %s\n", rrString)
	}
	
	if authCount == 0 {
		fmt.Printf("❌ Authority query returned 0 records\n")
		fmt.Println("This is why no Authority section appears in DNS responses!")
	} else {
		fmt.Printf("✓ Authority query returned %d records\n", authCount)
		fmt.Println("Authority records should appear in DNS responses")
	}
	
	fmt.Println("\n=== Debug Complete ===")
}