// Package main implements a one-shot replay tool for the AI-driven version-diff
// scanner. Given a database connection string and a list of (new_id, old_id)
// pairs, it dials the local scanner-bridge, calls ScanArtifactDiff for each pair,
// and writes results to a CSV. Used in Phase 7.5 of the version-diff rebuild
// before production rollout.
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var (
		dbURL       = flag.String("db", "", "Database URL (sqlite path or postgres DSN)")
		driver      = flag.String("driver", "sqlite3", "sqlite3 | postgres")
		socket      = flag.String("socket", "/tmp/shieldoo-bridge.sock", "Bridge socket")
		outCSV      = flag.String("out", "replay-results.csv", "Output CSV path")
		limit       = flag.Int("limit", 100, "Max pairs to replay")
		ecosys      = flag.String("ecosystem", "", "Restrict to one ecosystem (optional)")
		concurrency = flag.Int("concurrency", 4, "Parallel scans (caps OpenAI burst; bridge has 64 worker slots)")
		publicOnly  = flag.Bool("public-only", true, "Only replay pairs whose upstream_url is a public registry (PyPI, npm, NuGet, Maven Central, RubyGems). Set to false explicitly to include private-registry packages — REQUIRES OPERATOR CONSENT.")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("--db is required")
	}

	db, err := sql.Open(*driver, *dbURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	conn, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close()
	client := pb.NewScannerBridgeClient(conn)

	// Pull SUSPICIOUS pairs. Default: only public registries (privacy/compliance).
	q := `SELECT vdr.artifact_id, vdr.previous_artifact,
	             a_new.ecosystem, a_new.name, a_new.version,
	             a_new.sha256, a_new.storage_path,
	             a_old.version, a_old.sha256, a_old.storage_path
	        FROM version_diff_results vdr
	        JOIN artifacts a_new ON a_new.id = vdr.artifact_id
	        JOIN artifacts a_old ON a_old.id = vdr.previous_artifact
	       WHERE vdr.verdict = 'SUSPICIOUS'`
	args := []any{}
	if *ecosys != "" {
		q += " AND a_new.ecosystem = ?"
		args = append(args, *ecosys)
	}
	if *publicOnly {
		q += ` AND (a_new.upstream_url LIKE 'https://pypi.org/%'
		         OR a_new.upstream_url LIKE 'https://files.pythonhosted.org/%'
		         OR a_new.upstream_url LIKE 'https://registry.npmjs.org/%'
		         OR a_new.upstream_url LIKE 'https://api.nuget.org/%'
		         OR a_new.upstream_url LIKE 'https://repo1.maven.org/%'
		         OR a_new.upstream_url LIKE 'https://repo.maven.apache.org/%'
		         OR a_new.upstream_url LIKE 'https://rubygems.org/%')`
	} else {
		fmt.Fprintln(os.Stderr,
			"WARNING: --public-only=false will send PRIVATE-REGISTRY package contents to Azure OpenAI.")
		fmt.Fprintln(os.Stderr,
			"         Confirm with security/compliance before proceeding. Press Ctrl-C within 10 s to abort.")
		time.Sleep(10 * time.Second)
	}
	q += " ORDER BY vdr.diff_at DESC LIMIT ?"
	args = append(args, *limit)
	q = rebind(q, *driver)

	rows, err := db.Query(q, args...)
	if err != nil {
		log.Fatalf("query: %v", err)
	}
	defer rows.Close()

	out, err := os.Create(*outCSV)
	if err != nil {
		log.Fatalf("create csv: %v", err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{
		"artifact_id", "previous_artifact", "ecosystem", "name", "new_version", "old_version",
		"new_verdict", "ai_verdict", "ai_confidence", "ai_findings", "ai_explanation", "tokens_used",
		"flipped_to_clean",
	})

	type row struct {
		newID, prevID                      string
		eco, name, newVer, newSHA, newPath string
		oldVer, oldSHA, oldPath            string
	}
	var pairs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.newID, &r.prevID, &r.eco, &r.name, &r.newVer,
			&r.newSHA, &r.newPath, &r.oldVer, &r.oldSHA, &r.oldPath); err != nil {
			log.Fatalf("scan: %v", err)
		}
		pairs = append(pairs, r)
	}

	// Worker pool to cap OpenAI burst and bridge load.
	type job struct {
		i int
		r row
	}
	jobs := make(chan job, len(pairs))
	for i, r := range pairs {
		jobs <- job{i: i, r: r}
	}
	close(jobs)

	var csvMu sync.Mutex
	var wg sync.WaitGroup
	for w_id := 0; w_id < *concurrency; w_id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := j.r
				if _, err := os.Stat(r.newPath); err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — new artifact not on disk: %v\n", j.i+1, len(pairs), r.newID, err)
					continue
				}
				if _, err := os.Stat(r.oldPath); err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — previous artifact not on disk: %v\n", j.i+1, len(pairs), r.prevID, err)
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				req := &pb.DiffScanRequest{
					ArtifactId:         r.newID,
					Ecosystem:          r.eco,
					Name:               r.name,
					Version:            r.newVer,
					PreviousVersion:    r.oldVer,
					LocalPath:          r.newPath,
					PreviousPath:       r.oldPath,
					LocalPathSha256:    strings.ToLower(r.newSHA),
					PreviousPathSha256: strings.ToLower(r.oldSHA),
				}
				resp, err := client.ScanArtifactDiff(ctx, req)
				cancel()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — bridge error: %v\n", j.i+1, len(pairs), r.newID, err)
					continue
				}

				flipped := "no"
				if resp.Verdict == "CLEAN" {
					flipped = "yes"
				}
				csvMu.Lock()
				_ = w.Write([]string{
					r.newID, r.prevID, r.eco, r.name, r.newVer, r.oldVer,
					"SUSPICIOUS",
					resp.Verdict, fmt.Sprintf("%.4f", resp.Confidence),
					strings.Join(resp.Findings, " | "),
					resp.Explanation,
					fmt.Sprintf("%d", resp.TokensUsed),
					flipped,
				})
				w.Flush()
				csvMu.Unlock()
				fmt.Printf("[%d/%d] %s/%s %s→%s : %s (conf=%.2f)\n",
					j.i+1, len(pairs), r.eco, r.name, r.oldVer, r.newVer, resp.Verdict, resp.Confidence)
			}
		}()
	}
	wg.Wait()
}

func rebind(q, driver string) string {
	if driver != "postgres" {
		return q
	}
	out := strings.Builder{}
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			fmt.Fprintf(&out, "$%d", n)
			continue
		}
		out.WriteRune(c)
	}
	return out.String()
}
