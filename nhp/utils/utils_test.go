package utils

import (
	"testing"
)

func TestIsValidPathComponent(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"file.txt", true},
		{"uuid-1234", true},
		{".hidden", true},
		{"a", true},
		{"", false},
		{".", false},
		{"..", false},
	}
	for _, tt := range tests {
		got := IsValidPathComponent(tt.input)
		if got != tt.want {
			t.Errorf("IsValidPathComponent(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsPathWithinDir(t *testing.T) {
	tests := []struct {
		absPath string
		dirAbs  string
		want    bool
	}{
		{"/a/b/c", "/a/b", true},
		{"/a/b/c/d", "/a/b", true},
		{"/a/b", "/a/b", false},   // exact match is not "within"
		{"/a/bc", "/a/b", false},  // prefix but not directory boundary
		{"/x/y/z", "/a/b", false}, // completely different path
		{"/a/b/", "/a/b", true},   // trailing separator means within dir
	}
	for _, tt := range tests {
		got := IsPathWithinDir(tt.absPath, tt.dirAbs)
		if got != tt.want {
			t.Errorf("IsPathWithinDir(%q, %q) = %v, want %v", tt.absPath, tt.dirAbs, got, tt.want)
		}
	}
}
