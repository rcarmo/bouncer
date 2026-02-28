package token

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(tok) != 6 {
		t.Errorf("expected 6 chars, got %d: %q", len(tok), tok)
	}
	for _, c := range tok {
		if c < '0' || c > '9' {
			t.Errorf("non-digit char %q in token %q", c, tok)
		}
	}
}

func TestGenerateUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := Generate()
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		seen[tok] = true
	}
	// With 1M possible values, 100 draws should be nearly all unique.
	if len(seen) < 90 {
		t.Errorf("expected >90 unique tokens from 100 draws, got %d", len(seen))
	}
}
