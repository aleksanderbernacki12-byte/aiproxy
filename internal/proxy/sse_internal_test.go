package proxy

import (
	"io"
	"testing"
)

type reviewChunks struct {
	chunks []string
	reads  int
}

func (r *reviewChunks) Read(p []byte) (int, error) {
	r.reads++
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func (r *reviewChunks) Close() error { return nil }

func TestReview_StreamMustRecognizeCRLFBoundaries(t *testing.T) {
	src := &reviewChunks{chunks: []string{"data: first\r\n\r\n", "data: second\r\n\r\n"}}
	tee := &streamTee{src: src}
	var p [4096]byte
	n, err := tee.Read(p[:])
	if err != nil {
		t.Fatal(err)
	}
	if src.reads != 1 {
		t.Fatalf("first read consumed %d upstream reads including EOF instead of emitting first event: %q", src.reads, p[:n])
	}
}

func TestLastEventBoundary(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		atEOF bool
		want  int
	}{
		{"LF", "data: a\n\ndata: b", false, 9},
		{"CRLF", "data: a\r\n\r\ndata: b", false, 11},
		{"CR", "data: a\r\rdata: b", false, 9},
		{"mixed", "data: a\r\n\ndata: b\n\r\n", false, 20},
		{"last of two", "a\n\nb\n\nc", false, 6},
		{"no boundary", "data: a\ndata: b\n", false, -1},
		{"trailing CR may be half of CRLF", "data: a\r\n\r", false, -1},
		{"trailing CR at EOF is a boundary", "data: a\r\n\r", true, 10},
		{"empty", "", false, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastEventBoundary([]byte(tc.data), tc.atEOF); got != tc.want {
				t.Fatalf("lastEventBoundary(%q, %v) = %d, want %d", tc.data, tc.atEOF, got, tc.want)
			}
		})
	}
}

func TestStreamTee_CRLFSplitAcrossReadsIsOneBoundary(t *testing.T) {
	src := &reviewChunks{chunks: []string{"data: a\r\n\r", "\ndata: b\r\n\r\n"}}
	tee := &streamTee{src: src}
	out, err := io.ReadAll(tee)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "data: a\r\n\r\ndata: b\r\n\r\n" {
		t.Fatalf("stream bytes changed: %q", out)
	}
}
