package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestModes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code := run([]string{"dance"}, &out, &errb); code != 2 {
		t.Errorf("unknown mode: %d", code)
	}
	if code := run([]string{"bench", "-zz"}, &out, &errb); code != 1 {
		t.Errorf("bad flag: %d", code)
	}
	out.Reset()
	code := run([]string{"bench", "-n", "1000"}, &out, &errb)
	if runtime.GOOS != "linux" {
		if code != 1 || !strings.Contains(errb.String(), "Linux") {
			t.Errorf("non-linux bench: %d %q", code, errb.String())
		}
		return
	}
	var res BenchResult
	if code != 0 || json.Unmarshal(out.Bytes(), &res) != nil || res.N != 1000 || res.NsPerOp <= 0 {
		t.Errorf("bench: %d %q", code, out.String())
	}
}
