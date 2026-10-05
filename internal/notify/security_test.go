package notify

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

func TestExternalResponseBudgets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
	}{
		{"JSON", maxExternalJSONBytes}, {"page", maxUpdatePageBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Chunked responses exercise actual bytes rather than Content-Length.
				w.(http.Flusher).Flush()
				_, _ = io.CopyN(w, strings.NewReader(strings.Repeat(" ", int(tc.limit)+1)), tc.limit+1)
			}))
			defer server.Close()
			var err error
			if tc.name == "JSON" {
				_, err = LookupGeoIP(context.Background(), config.GeoIPConfig{Enabled: true, URL: server.URL + "/%s"}, "1.2.3.4")
			} else {
				p := &DBIPProvider{cfg: config.DBIPConfig{UpdatePageURL: server.URL}}
				_, err = p.resolveUpdateURL(context.Background())
			}
			if err == nil || !strings.Contains(err.Error(), "byte budget") {
				t.Fatalf("expected size error, got %v", err)
			}
		})
	}
	// A valid JSON prefix must not hide an oversized trailing body.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}"+strings.Repeat(" ", int(maxExternalJSONBytes)))
	}))
	defer server.Close()
	if _, err := LookupGeoIP(context.Background(), config.GeoIPConfig{Enabled: true, URL: server.URL + "/%s"}, "1.2.3.4"); err == nil {
		t.Fatal("accepted oversized JSON suffix")
	}
}

func TestCSVBudgets(t *testing.T) {
	for _, tc := range []struct {
		name, input  string
		record, rows int
		wantErr      bool
	}{
		{"exact", "a,b\n", 4, 1, false},
		{"last without newline", "a,b", 3, 1, false},
		{"multiline escaped", "a,\"b\n\"\"c\"\"\",d\r\nx,y,z\n", 64, 2, false},
		{"record", "a," + strings.Repeat("x", 65), 64, 2, true},
		{"quoted record", "a,\"" + strings.Repeat("x\n", 40) + "\"\n", 64, 2, true},
		{"rows", "a,b\na,b\n", 64, 1, true},
		{"blank rows", "\n\n", 64, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, originalErr := csv.NewReader(strings.NewReader(tc.input)).ReadAll()
			for _, r := range []io.Reader{strings.NewReader(tc.input), iotest.OneByteReader(strings.NewReader(tc.input))} {
				got, err := csv.NewReader(newCSVBudget(r, tc.record, tc.rows)).ReadAll()
				if tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
						t.Fatalf("expected budget error, got %v", err)
					}
				} else {
					if err != nil || originalErr != nil {
						t.Fatalf("valid CSV failed: %v / %v", err, originalErr)
					}
					if len(got) != len(original) {
						t.Fatalf("record mismatch: %v / %v", got, original)
					}
					for i := range got {
						for j := range got[i] {
							if got[i][j] != original[i][j] {
								t.Fatalf("field mismatch: %v / %v", got, original)
							}
						}
					}
				}
			}
		})
	}
}

func TestByteAndDecompressionBudgets(t *testing.T) {
	for _, size := range []int{31, 32, 33} {
		_, err := readBounded(strings.NewReader(strings.Repeat("x", size)), 32)
		if (err != nil) != (size > 32) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(zw, strings.Repeat("a,b\n", 1024))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// Both the transport budget and expansion budget fail closed, not EOF.
	for _, tc := range []struct {
		name                 string
		compressed, expanded int64
	}{
		{"compressed", int64(compressed.Len() - 1), 8192},
		{"expanded", int64(compressed.Len()), 128},
		{"exact", int64(compressed.Len()), 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gz, err := gzip.NewReader(&byteBudget{reader: bytes.NewReader(compressed.Bytes()), remaining: tc.compressed})
			if err == nil {
				defer func() { _ = gz.Close() }()
				_, err = io.Copy(io.Discard, &byteBudget{reader: gz, remaining: tc.expanded})
			}
			if (err != nil) != (tc.name != "exact") {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestBuildRejectsOversizedRecord(t *testing.T) {
	p := &DBIPProvider{}
	err := p.buildDB(filepath.Join(t.TempDir(), "db.sqlite"), strings.NewReader("1.0.0.0,1.0.0.255,OC,AU,Region,\""+strings.Repeat("x\n", maxDBIPRecordBytes)+"\",0,0\n"), "test")
	if err == nil || !strings.Contains(err.Error(), "record byte budget") {
		t.Fatalf("expected bounded record failure: %v", err)
	}
}

func TestGeoCacheExpiryAndCapacity(t *testing.T) {
	c := &externalGeoCache{entries: make(map[string]*list.Element)}
	now := time.Now()
	info := &GeoInfo{Country: "AU"}
	c.put("expired", info, now.Add(time.Second), now)
	c.put("live", info, now.Add(time.Hour), now)
	if c.get("live", now.Add(2*time.Second)) != info {
		t.Fatal("live entry missing")
	}
	if _, ok := c.entries["expired"]; ok {
		t.Fatal("unrelated expired entry retained")
	}
	for i := 0; i < geoCacheCapacity; i++ {
		c.put(strconv.Itoa(i), info, now.Add(time.Hour), now)
	}
	if len(c.entries) != geoCacheCapacity || c.order.Len() != geoCacheCapacity {
		t.Fatal("cache capacity exceeded")
	}
	if c.get("live", now) != nil {
		t.Fatal("oldest entry not evicted")
	}
	if c.get("0", now.Add(2*time.Hour)) != nil || len(c.entries) != 0 || c.order.Len() != 0 {
		t.Fatal("expiry did not empty cache")
	}
}
