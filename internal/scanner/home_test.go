package scanner_test

import "testing"

// setHome points os.UserHomeDir at dir on every OS: it reads HOME on Unix
// and USERPROFILE on Windows.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}
