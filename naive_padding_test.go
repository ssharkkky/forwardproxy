package forwardproxy

import (
	"net/http"
	"testing"
)

func TestNegotiateNaivePadding(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		want    int
		wantErr bool
	}{
		{name: "legacy none", header: http.Header{}, want: naivePaddingNone},
		{name: "legacy variant1", header: http.Header{"Padding": {"cover"}}, want: naivePaddingVariant1},
		{name: "prefer variant1", header: http.Header{"Padding-Type-Request": {"1, 0"}}, want: naivePaddingVariant1},
		{name: "request none", header: http.Header{"Padding-Type-Request": {"0"}}, want: naivePaddingNone},
		{name: "respect client order", header: http.Header{"Padding-Type-Request": {"0, 1"}}, want: naivePaddingNone},
		{name: "invalid type", header: http.Header{"Padding-Type-Request": {"2, 1"}}, wantErr: true},
		{name: "empty type", header: http.Header{"Padding-Type-Request": {""}}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := negotiateNaivePadding(test.header)
			if test.wantErr {
				if err == nil {
					t.Fatalf("negotiateNaivePadding() = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("negotiateNaivePadding() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("negotiateNaivePadding() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestSetNaivePaddingResponseHeaders(t *testing.T) {
	request := http.Header{"Padding-Type-Request": {"1, 0"}}
	response := make(http.Header)
	setNaivePaddingResponseHeaders(response, request, naivePaddingVariant1)

	if got := response.Get("Padding-Type-Reply"); got != "1" {
		t.Fatalf("Padding-Type-Reply = %q, want 1", got)
	}
	if got := len(response.Get("Padding")); got < 30 || got >= 62 {
		t.Fatalf("Padding length = %d, want [30, 62)", got)
	}
}
