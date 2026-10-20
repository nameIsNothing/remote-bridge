//go:build windows

package main

import "testing"

func TestJoinWindowsArgsForTrustChild(t *testing.T) {
	got := joinWindowsArgs([]string{"trust", "--target", "192.168.100.27", "--uac-child"})
	if got != "trust --target 192.168.100.27 --uac-child" {
		t.Fatalf("arguments = %q", got)
	}
}

func TestQuoteWindowsArgProtectsWhitespaceAndQuotes(t *testing.T) {
	if got := quoteWindowsArg("plain"); got != "plain" {
		t.Fatalf("plain argument = %q", got)
	}
	if got := quoteWindowsArg(`C:\Program Files\Remote Bridge\bridge-cli.exe`); got != `"C:\Program Files\Remote Bridge\bridge-cli.exe"` {
		t.Fatalf("path argument = %q", got)
	}
	if got := quoteWindowsArg(`a"b`); got != `"a\"b"` {
		t.Fatalf("quoted argument = %q", got)
	}
}
