package notify

import (
	"fmt"
	"io"
)

// Fixed budgets allow streamed city/country databases without buffering the
// download. 512 MiB compressed / 4 GiB expanded / 20 million logical rows leave
// headroom for DBIP Lite; each CSV record is limited to 64 KiB (including quoted
// newlines). Small external API JSON and discovery HTML have separate caps.
const (
	maxExternalJSONBytes   int64 = 1 << 20
	maxUpdatePageBytes     int64 = 2 << 20
	maxDBIPCompressedBytes int64 = 512 << 20
	maxDBIPExpandedBytes   int64 = 4 << 30
	maxDBIPRecordBytes           = 64 << 10
	maxDBIPRows                  = 20_000_000
)

// byteBudget reports overflow rather than a synthetic EOF, which could accept
// truncated CSV or gzip streams. At the boundary it probes only one extra byte.
type byteBudget struct {
	reader    io.Reader
	remaining int64
}

func (b *byteBudget) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.reader.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("notify: response byte budget exceeded")
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:int(b.remaining)]
	}
	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(&byteBudget{reader: r, remaining: limit})
}

// csvBudget validates raw logical record boundaries before encoding/csv can
// allocate an unbounded record. It streams chunks, tracks RFC4180 quoted fields
// (including doubled quotes and embedded CRLF), and leaves syntax validation to
// encoding/csv. No copy or allocation is needed per record. Blank/invalid rows
// also consume the row budget, so skipped IPv6 records cannot bypass it.
type csvBudget struct {
	reader                         io.Reader
	recordLimit, rowLimit          int
	recordBytes, rows              int
	quoted, afterQuote, fieldStart bool
}

func newCSVBudget(r io.Reader, recordLimit, rowLimit int) *csvBudget {
	return &csvBudget{reader: r, recordLimit: recordLimit, rowLimit: rowLimit, fieldStart: true}
}
func (b *csvBudget) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	for i, ch := range p[:n] {
		if b.recordBytes == 0 {
			if b.rows >= b.rowLimit {
				return i, fmt.Errorf("dbip: CSV row budget exceeded")
			}
			b.rows++
		}
		b.recordBytes++
		if b.recordBytes > b.recordLimit {
			return i, fmt.Errorf("dbip: CSV record byte budget exceeded")
		}
		if b.quoted {
			if ch == '"' {
				b.quoted = false
				b.afterQuote = true
			}
			continue
		}
		if b.afterQuote {
			b.afterQuote = false
			if ch == '"' {
				b.quoted = true
				continue
			}
		}
		switch ch {
		case '"':
			if b.fieldStart {
				b.quoted = true
			}
			b.fieldStart = false
		case ',':
			b.fieldStart = true
		case '\n':
			b.recordBytes = 0
			b.fieldStart = true
		default:
			b.fieldStart = false
		}
	}
	return n, err
}
