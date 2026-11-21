package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTitusDetectsKnownToken(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	secret := filepath.Join(dir, "secret.txt")
	_ = os.WriteFile(clean, []byte("hello world\n"), 0o644)
	_ = os.WriteFile(secret, []byte("token = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"), 0o644)
	excluded, err := engine.DetectPath(context.Background(), clean)
	if err != nil || excluded {
		t.Fatalf("clean: excluded=%v err=%v", excluded, err)
	}
	excluded, err = engine.DetectPath(context.Background(), secret)
	if err != nil || !excluded {
		t.Fatalf("secret: excluded=%v err=%v", excluded, err)
	}
}

func TestTitusExcludesNoisyRules(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	scanner, err := engine.ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rules := scanner.Rules()
	if len(rules) == 0 {
		t.Fatal("expected builtin rules to be loaded")
	}
	sawNonNoisy := false
	for _, r := range rules {
		if r.Noisy {
			t.Errorf("rule %s must be filtered out by NewTitus", r.ID)
		}
		switch {
		case strings.HasPrefix(r.ID, "np.pem."),
			strings.HasPrefix(r.ID, "np.aws."),
			strings.HasPrefix(r.ID, "np.github."):
			sawNonNoisy = true
		}
	}
	if !sawNonNoisy {
		t.Fatal("expected non-noisy np.pem/np.aws/np.github rules to remain")
	}

	dir := t.TempDir()
	card := filepath.Join(dir, "card.txt")
	if err := os.WriteFile(card, []byte("The payment card number 4111111111111111 belongs to a test account.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excluded, err := engine.DetectPath(context.Background(), card)
	if err != nil {
		t.Fatal(err)
	}
	if excluded {
		t.Fatal("4111111111111111 must not be excluded after noisy rules are filtered")
	}

	// 4111111111111111 is on the CCN rule's ignore list, so it cannot show that
	// noisy rules were removed. This different Luhn-valid Visa number fires
	// under the unfiltered np.ccn.* rules, proving they are what NewTitus drops.
	otherCard := filepath.Join(dir, "other-card.txt")
	if err := os.WriteFile(otherCard, []byte("The payment card number 4532015112830366 belongs to a test account.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excluded, err = engine.DetectPath(context.Background(), otherCard)
	if err != nil {
		t.Fatal(err)
	}
	if excluded {
		t.Fatal("4532015112830366 must not be excluded after noisy rules are filtered")
	}
}

func TestTitusDetectPathMissingFile(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	excluded, err := engine.DetectPath(context.Background(), filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if excluded {
		t.Fatal("expected excluded=false for missing file")
	}
}

func TestTitusDetectPathCanceledContext(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	_ = os.WriteFile(path, []byte("hello world\n"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	excluded, err := engine.DetectPath(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got err=%v", err)
	}
	if excluded {
		t.Fatal("expected excluded=false for canceled context")
	}
}

func TestTitusCloseTwice(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestTitusDetectPathAfterClose(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	_ = os.WriteFile(path, []byte("hello world\n"), 0o644)
	excluded, err := engine.DetectPath(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for DetectPath after close")
	}
	if excluded {
		t.Fatal("expected excluded=false for DetectPath after close")
	}
}

func TestTitusConcurrentDetectPath(t *testing.T) {
	engine, err := NewTitus()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	secret := filepath.Join(dir, "secret.txt")
	_ = os.WriteFile(clean, []byte("hello world\n"), 0o644)
	_ = os.WriteFile(secret, []byte("token = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"), 0o644)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			excluded, err := engine.DetectPath(context.Background(), clean)
			if err != nil {
				errs <- fmt.Errorf("clean: %w", err)
				return
			}
			if excluded {
				errs <- errors.New("clean: got excluded=true")
			}
		}()
		go func() {
			defer wg.Done()
			excluded, err := engine.DetectPath(context.Background(), secret)
			if err != nil {
				errs <- fmt.Errorf("secret: %w", err)
				return
			}
			if !excluded {
				errs <- errors.New("secret: got excluded=false")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
