package database

import (
	"fmt"
	"strconv"
	"strings"
)

// sqliteMaxVars is kept below SQLite's SQLITE_MAX_VARIABLE_NUMBER, which is
// 999 in some builds and 32766 in others. Multi-row inserts stay under this.
const sqliteMaxVars = 900

// URLRecord is the write-side shape for persisting discovered URLs.
type URLRecord struct {
	Domain      string
	URL         string
	Category    string
	Source      string
	Interesting int
}

func insertBatchSize(columns int) int {
	if columns < 1 {
		return 1
	}
	size := sqliteMaxVars / columns
	if size < 1 {
		return 1
	}
	return size
}

func forInsertBatches(n, columns int, fn func(start, end int) error) error {
	if n == 0 {
		return nil
	}
	batch := insertBatchSize(columns)
	for start := 0; start < n; start += batch {
		end := start + batch
		if end > n {
			end = n
		}
		if err := fn(start, end); err != nil {
			return err
		}
	}
	return nil
}

func valuePlaceholders(rows, cols int) string {
	if rows <= 0 || cols <= 0 {
		return ""
	}
	tuple := "(" + strings.Repeat("?,", cols-1) + "?)"
	var b strings.Builder
	b.Grow((len(tuple) + 1) * rows)
	for i := 0; i < rows; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(tuple)
	}
	return b.String()
}

// AddSubdomains upserts many subdomains in multi-row INSERT batches.
func (r *DomainRepository) AddSubdomains(domainID int64, subdomains []string) error {
	if len(subdomains) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(subdomains))
	unique := make([]string, 0, len(subdomains))
	for _, sub := range subdomains {
		if sub == "" {
			continue
		}
		if _, ok := seen[sub]; ok {
			continue
		}
		seen[sub] = struct{}{}
		unique = append(unique, sub)
	}
	if len(unique) == 0 {
		return nil
	}

	const cols = 2
	return forInsertBatches(len(unique), cols, func(start, end int) error {
		batch := unique[start:end]
		args := make([]interface{}, 0, len(batch)*cols)
		for _, sub := range batch {
			args = append(args, domainID, sub)
		}
		query := `INSERT INTO subdomains (domain_id, subdomain) VALUES ` +
			valuePlaceholders(len(batch), cols) +
			` ON CONFLICT(domain_id, subdomain) DO UPDATE SET last_seen = CURRENT_TIMESTAMP, active = 1`
		_, err := r.db.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("inserting subdomains: %w", err)
		}
		return nil
	})
}

// AddAll upserts many ports in multi-row INSERT batches.
func (r *PortRepository) AddAll(ports []Port) error {
	if len(ports) == 0 {
		return nil
	}

	seen := make(map[string]int, len(ports))
	unique := make([]Port, 0, len(ports))
	for _, p := range ports {
		key := p.Host + "\x00" + strconv.Itoa(p.Port) + "\x00" + p.Protocol
		if i, ok := seen[key]; ok {
			unique[i] = p
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, p)
	}

	const cols = 8
	return forInsertBatches(len(unique), cols, func(start, end int) error {
		batch := unique[start:end]
		args := make([]interface{}, 0, len(batch)*cols)
		for _, p := range batch {
			args = append(args, p.Host, p.Port, p.Protocol, p.Service, p.Version, p.Product, p.State, p.Banner)
		}
		query := `INSERT INTO ports (host, port, protocol, service, version, product, state, banner) VALUES ` +
			valuePlaceholders(len(batch), cols) +
			` ON CONFLICT(host, port, protocol) DO UPDATE SET
				service = excluded.service,
				version = excluded.version,
				product = excluded.product,
				state = excluded.state,
				banner = excluded.banner,
				last_seen = CURRENT_TIMESTAMP`
		_, err := r.db.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("inserting ports: %w", err)
		}
		return nil
	})
}

// SaveURLs upserts many discovered URLs in multi-row INSERT batches.
func (d *Database) SaveURLs(records []URLRecord) error {
	return saveURLs(d.db, records)
}

// SaveURLs upserts many discovered URLs in this transaction.
func (tx *Transaction) SaveURLs(records []URLRecord) error {
	return saveURLs(tx.db, records)
}

func saveURLs(db queryExecutor, records []URLRecord) error {
	if len(records) == 0 {
		return nil
	}

	seen := make(map[string]int, len(records))
	unique := make([]URLRecord, 0, len(records))
	for _, rec := range records {
		if rec.URL == "" {
			continue
		}
		if i, ok := seen[rec.URL]; ok {
			unique[i] = rec
			continue
		}
		seen[rec.URL] = len(unique)
		unique = append(unique, rec)
	}
	if len(unique) == 0 {
		return nil
	}

	const cols = 5
	return forInsertBatches(len(unique), cols, func(start, end int) error {
		batch := unique[start:end]
		args := make([]interface{}, 0, len(batch)*cols)
		for _, rec := range batch {
			args = append(args, rec.Domain, rec.URL, rec.Category, rec.Interesting, rec.Source)
		}
		query := `INSERT INTO urls (domain, url, category, interesting, source) VALUES ` +
			valuePlaceholders(len(batch), cols) +
			` ON CONFLICT(url) DO UPDATE SET
				category = excluded.category,
				interesting = excluded.interesting,
				source = excluded.source`
		_, err := db.Exec(query, args...)
		if err != nil {
			return fmt.Errorf("inserting URLs: %w", err)
		}
		return nil
	})
}
