package main

import (
	"bytes"
	"testing"
)

func page(segments ...[]byte) []byte {
	var lacing, body []byte
	for _, s := range segments {
		lacing = append(lacing, byte(len(s)))
		body = append(body, s...)
	}
	head := make([]byte, 27)
	copy(head, "OggS")
	head[26] = byte(len(lacing))
	return append(append(head, lacing...), body...)
}

func TestOggPacketsAcrossPages(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 255+10)
	file := page([]byte("OpusHead..."), []byte{0xF8, 1, 2})
	// A packet of 265 bytes is a 255 segment, which continues on the next page.
	file = append(file, page(long[:255])...)
	file = append(file, page(long[255:], []byte{0xF8, 9})...)
	var got [][]byte
	if err := oggPackets(bytes.NewReader(file), func(p []byte) error { got = append(got, p); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || string(got[0]) != "OpusHead..." || !bytes.Equal(got[2], long) || !bytes.Equal(got[3], []byte{0xF8, 9}) {
		t.Fatalf("packets: %d %q", len(got), got)
	}
	if err := oggPackets(bytes.NewReader([]byte("not ogg at all, definitely not")), func([]byte) error { return nil }); err == nil {
		t.Fatal("a non-Ogg file was accepted")
	}
}
