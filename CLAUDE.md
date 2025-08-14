# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `coredns_mysql_extend`, a CoreDNS plugin that uses MySQL as a backend to store DNS records. The plugin extends CoreDNS with MySQL database support, providing high availability DNS resolution with fallback mechanisms and caching.

**Key Features:**
- MySQL backend for DNS record storage
- Connection pooling with configurable parameters
- Degraded operation mode with local JSON file fallback
- Support for wildcard domains and CNAME resolution
- DNSSEC support with RRSIG records
- NS record glue record handling
- CAA record inheritance from parent domains
- Comprehensive metrics and debug logging

## Architecture

**Core Components:**
- `mysql.go` - Main DNS resolution logic and ServeDNS implementation
- `init.go` - Plugin configuration parsing and database table creation
- `types.go` - Data structures (Mysql, mysqlConfig, record, dnsRecordInfo)
- `utils.go` - Helper functions for domain parsing and DNS record creation
- `setup.go` - CoreDNS plugin initialization and registration
- `hooks.go` - Database lifecycle management and background tasks
- `metrics.go` - Prometheus metrics collection
- `const.go` - Constants and default configuration values

**Database Schema:**
- `zones` table: stores DNS zones (id, zone_name)
- `records` table: stores DNS records (id, zone_id, hostname, type, data, ttl, online)

## Recent Changes

**Authority Section Implementation (2025-08-14)**
- Modified `MakeMessage()` function to include Authority section with NS records
- Added `getAuthorityRecords()` helper function to fetch zone NS records
- Added `getGlueRecords()` helper function to fetch A/AAAA records for authority NS records
- Updated all DNS response paths to include proper Authority and Additional sections
- Fixed hostname lookup bug (empty string → `"@"` for zone apex records)
- Now responds like a proper authoritative nameserver matching BIND behavior

## Development Commands

### Building the Plugin

Use the Just build system (Justfile) for all build operations:

```bash
# Build for current platform
just build

# Build for multiple architectures
just multi-arch

# Quick rebuild after code changes
just rebuild

# Clean build artifacts
just clean
```

### Development Workflow

```bash
# Development cycle: rebuild and run with debug
just dev

# Run CoreDNS with the plugin
just run

# Test build was successful
just test-build

# Check plugin is properly integrated
just check-plugin
```

### Docker Development

```bash
# Build Docker image
docker build -t coredns-mysql .

# Run with environment variables
docker run -e MYSQL_HOST=localhost -e MYSQL_USER=coredns coredns-mysql
```

### Testing DNS Resolution

```bash
# Basic DNS queries for testing
dig @127.0.0.1 -p 1053 example.com A
dig @127.0.0.1 -p 1053 example.com NS
dig @127.0.0.1 -p 1053 example.com SOA
dig @127.0.0.1 -p 1053 example.com CAA
```

## Configuration

### Corefile Configuration

The plugin is configured in the Corefile with these options:

```
mysql {
    dsn "username:password@tcp(127.0.0.1:3306)/dns"
    dump_file "/tmp/dns_cache.json"
    ttl 360
    zones_table "zones"
    records_table "records"
    fallthrough
}
```

### Database Connection Pool Settings

```
db_max_idle_conns 4
db_max_open_conns 8
db_conn_max_idle_time 1h
db_conn_max_life_time 24h
```

### Heartbeat and Health Check Settings

```
fail_heartbeat_time 10s
success_heartbeat_time 60s
```

## Code Architecture Details

### DNS Resolution Flow (mysql.go:51-568)

1. **Query Processing**: Extract FQDN, type, and client info
2. **Zone Lookup**: Find matching zone and decompose hostname
3. **Special Record Handling**: 
   - CAA records walk parent hierarchy
   - DNSKEY records checked at zone apex
4. **Database Query**: Direct record lookup with fallback to CNAME
5. **Wildcard Resolution**: If no exact match, try wildcard patterns
6. **Glue Record Collection**: For NS records, gather A/AAAA glue
7. **Cache Management**: Store results in degraded operation cache
8. **Response Generation**: Build DNS response with proper sections

### Plugin Integration (setup.go)

The plugin registers with CoreDNS using the standard plugin interface:
- `Name()` returns plugin identifier
- `ServeDNS()` handles DNS queries  
- Configuration parsed from Corefile blocks

### Database Schema Management (init.go:150-186)

Auto-creates required tables if they don't exist:
- Foreign key relationship between zones and records
- Support for online/offline record states
- Configurable table names

## Debugging and Logging

### Enable Debug Logging

Set debug mode in Corefile:
```
debug
```

### Key Log Patterns

The plugin uses structured logging with timestamps. Look for:
- `New query:` - Incoming DNS requests
- `Zone lookup:` - Domain to zone resolution
- `Database query:` - MySQL operations  
- `Cache hit/miss:` - Degraded operation cache
- `Response decision:` - Final response type

### Common Issues

- **Database Connection**: Check DSN format and MySQL connectivity
- **Zone Resolution**: Ensure zones table populated correctly
- **Plugin Order**: Place mysql plugin early in plugin.cfg
- **Fallthrough**: Configure appropriately to avoid infinite loops

## Metrics

Prometheus metrics are available at standard CoreDNS metrics endpoint:
- `mysql_query_total` - Database query counts by status
- `mysql_zone_find_total` - Zone resolution attempts  
- `mysql_degrade_cache_total` - Cache operations
- `mysql_db_ping_total` - Database health checks

## Environment Variables (Docker)

When using Docker, these environment variables are supported:
- `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_HOST`, `MYSQL_PORT`
- `MYSQL_DATABASE`, `MYSQL_TABLE_PREFIX`
- Corresponding `*_FILE` versions for Docker secrets