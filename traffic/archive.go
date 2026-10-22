package traffic

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Large content-addressed bodies are copied alongside this manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Exchanges []ArchiveExchange `json:"exchanges"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqLen      int    `json:"req_len"`
	RespLen     int    `json:"resp_len"`
	ReqHead     string `json:"req_head"`
	ReqBody     []byte `json:"req_body,omitempty"`
	ReqBlob     string `json:"req_blob,omitempty"`
	RespHead    string `json:"resp_head"`
	RespBody    []byte `json:"resp_body,omitempty"`
	RespBlob    string `json:"resp_blob,omitempty"`
}

// ExportHosts writes an exact-host snapshot to dir. It holds the traffic writer
// lock while reading SQLite and blobs, so each body and its index row come from
// one consistent point in time.
//
// Rows and bodies are read in one join rather than one lookup per exchange, and
// bodies are streamed to disk instead of buffered: a host's capture can hold
// thousands of exchanges, and the per-row query plus a second copy of every
// blob in memory is what made a large export both slow and memory-hungry.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	unique := uniqueArchiveHosts(hosts)
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		args[i] = host
	}
	rows, err := t.db.Query(`SELECT e.id,e.ts,e.host,e.method,e.url_template,e.url,e.status,e.content_type,e.req_len,e.resp_len,e.path,
       b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob
FROM exchanges e LEFT JOIN exchange_bodies b ON b.id=e.id
WHERE e.host IN (`+strings.Join(placeholders, ",")+`) ORDER BY e.ts,e.id`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	snapshot := ArchiveSnapshot{Version: 1}
	blobs := map[string]struct{}{}
	for rows.Next() {
		var item ArchiveExchange
		var legacyPath string
		var reqHead, reqBlob, respHead, respBlob sql.NullString
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath,
			&reqHead, &item.ReqBody, &reqBlob, &respHead, &item.RespBody, &respBlob); err != nil {
			return 0, err
		}
		if !reqHead.Valid && strings.TrimSpace(legacyPath) != "" && filepath.IsLocal(legacyPath) {
			req, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "request.http"))
			if readErr != nil && !os.IsNotExist(readErr) {
				return 0, readErr
			}
			resp, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "response.http"))
			if readErr != nil && !os.IsNotExist(readErr) {
				return 0, readErr
			}
			item.ReqHead, item.RespHead = string(req), string(resp)
		} else {
			item.ReqHead, item.RespHead = reqHead.String, respHead.String
		}
		item.ReqBlob, item.RespBlob = reqBlob.String, respBlob.String
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				blobs[hash] = struct{}{}
			}
		}
		snapshot.Exchanges = append(snapshot.Exchanges, item)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// Close before writing: the connection must go back to the pool while the
	// (possibly long) blob copy below still holds the write lock.
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for hash := range blobs {
		if err := t.copyBlobTo(hash, filepath.Join(dir, "blobs", hash+".bin")); err != nil {
			return 0, err
		}
		snapshot.Blobs = append(snapshot.Blobs, hash)
	}
	sort.Strings(snapshot.Blobs)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), raw, 0o600); err != nil {
		return 0, err
	}
	return int64(len(snapshot.Exchanges)), nil
}

// copyBlobTo streams one content-addressed body to destination without holding
// it in memory.
func (t *Traffic) copyBlobTo(hash, destination string) error {
	source, err := t.blobPath(hash)
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// importBlob verifies one archived body and installs it into the blob store.
// The hash is computed while streaming through a temp file, so verifying a
// multi-gigabyte body costs no more memory than verifying a small one, and a
// body that fails the checksum never reaches the live store.
func (t *Traffic) importBlob(dir, hash string) error {
	destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	if _, err := os.Stat(destination); err == nil {
		return nil // already present; content addressing makes it the same bytes
	}
	source, err := os.Open(filepath.Join(dir, "blobs", hash+".bin"))
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(filepath.Join(t.dir, "_blobs", "sha256", hash[:2]), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(t.dir, "_blobs", "sha256", hash[:2]), hash+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after the successful rename below
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, sum), source); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != hash {
		return fmt.Errorf("traffic blob checksum mismatch: %s", hash)
	}
	return os.Rename(tmpName, destination)
}

// maxArchiveManifest caps traffic.json. The manifest inlines every body below
// maxInlineBody, so a large host legitimately produces a large file — but an
// archive is a file another installation can hand us, and loading it must not be
// allowed to consume arbitrary memory. 1 GiB is far above any real capture and
// still bounded.
const maxArchiveManifest = 1 << 30

// ImportArchive imports only missing exchange IDs. Current hot rows always win,
// and repeated restore attempts are safe after a partial external failure.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	if t == nil {
		return 0, nil
	}
	manifest := filepath.Join(dir, "traffic.json")
	st, err := os.Stat(manifest)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if st.Size() > maxArchiveManifest {
		return 0, fmt.Errorf("流量归档清单过大（%d 字节，上限 %d）", st.Size(), int64(maxArchiveManifest))
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != 1 {
		return 0, fmt.Errorf("unsupported traffic archive version %d", snapshot.Version)
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, hash := range snapshot.Blobs {
		if !blobHashRe.MatchString(hash) {
			return 0, fmt.Errorf("invalid archived traffic blob %q", hash)
		}
		if err := t.importBlob(dir, hash); err != nil {
			return 0, err
		}
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var imported int64
	for _, item := range snapshot.Exchanges {
		res, err := tx.Exec(`INSERT OR IGNORE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, item.ReqHead, item.ReqBody, nullIfEmpty(item.ReqBlob),
			item.RespHead, item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			content := strings.Join([]string{item.URL, item.ReqHead, string(item.ReqBody), item.RespHead, string(item.RespBody)}, "\n")
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, content); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
