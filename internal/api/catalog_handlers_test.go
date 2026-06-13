package api

import "testing"

func TestCSVSafe_NeutralisesFormulas(t *testing.T) {
	cases := map[string]string{
		"=1+1":          "'=1+1",
		"+cmd":          "'+cmd",
		"-2":            "'-2",
		"@SUM(A1)":      "'@SUM(A1)",
		"\t=evil":       "'\t=evil",
		"GET":           "GET",
		"/api/v1/users": "/api/v1/users",
		"":              "",
		"normal text":   "normal text",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
