package secrets

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// FuzzSecretRoundTrip asserts that the hand-rolled JSON escaper and unescaper
// agree: for any UTF-8 input, Marshal then Unmarshal returns the original
// bytes, and the escaped form is itself valid JSON that the standard library
// decodes identically. This guards against escaping bugs that could corrupt a
// secret value or smuggle structure into the wire format.
func FuzzSecretRoundTrip(f *testing.F) {
	seeds := []string{
		"",
		"plain",
		"postgres://user:p@ss@host/db",
		"line\nbreak\ttab\rcarriage",
		"quote\"and\\backslash",
		"control\x00\x01\x1f",
		"snowman:☃ and 𝄞 clef",
		"ÿ",
		"emoji 😀 mixed with ascii",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		in := Secret(data)
		marshaled, err := in.MarshalJSON()
		if err != nil {
			// Marshal only rejects non-UTF-8 input; that must be the reason.
			if utf8.Valid(data) {
				t.Fatalf("MarshalJSON rejected valid UTF-8 %q: %v", data, err)
			}
			return
		}
		if !utf8.Valid(data) {
			t.Fatalf("MarshalJSON accepted non-UTF-8 input %x", data)
		}

		// The escaper's output must be spec-valid JSON.
		if !json.Valid(marshaled) {
			t.Fatalf("MarshalJSON produced invalid JSON %q for input %q", marshaled, data)
		}

		// The standard library must decode our escaped form to the same bytes.
		var viaStdlib string
		if err := json.Unmarshal(marshaled, &viaStdlib); err != nil {
			t.Fatalf("stdlib rejected our JSON %q: %v", marshaled, err)
		}
		if !bytes.Equal([]byte(viaStdlib), data) {
			t.Fatalf("stdlib roundtrip mismatch: got %q want %q", viaStdlib, data)
		}

		// Our own unescaper must recover the original bytes.
		var out Secret
		if err := out.UnmarshalJSON(marshaled); err != nil {
			t.Fatalf("UnmarshalJSON rejected our own output %q: %v", marshaled, err)
		}
		if !bytes.Equal([]byte(out), data) {
			t.Fatalf("roundtrip mismatch: got %q want %q", []byte(out), data)
		}
	})
}

// FuzzSecretUnmarshalDifferential feeds arbitrary bytes straight into the
// custom UnmarshalJSON. It must never panic, and whenever it accepts an input
// the standard library must accept the identical bytes and decode to the same
// value. Our parser is intentionally stricter (it rejects control characters,
// invalid UTF-8, and lone surrogates), so the reverse direction is not
// required — but being *more* permissive than encoding/json would be a bug.
func FuzzSecretUnmarshalDifferential(f *testing.F) {
	seeds := []string{
		`""`,
		`"plain"`,
		`"escaped \" quote"`,
		`"\\ \/ \b \f \n \r \t"`,
		`"A☃"`,
		`"𝄞"`, // valid surrogate pair
		`"\uD834"`,       // lone high surrogate
		`"\uDD1E"`,       // lone low surrogate
		`"raw ☃ utf8"`,
		`"unterminated`,
		`"bad \x escape"`,
		`"\u00"`, // short unicode escape
		`not a string`,
		`"ctl` + "\x01" + `"`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var out Secret
		ourErr := out.UnmarshalJSON(data) // must not panic

		var viaStdlib string
		stdErr := json.Unmarshal(data, &viaStdlib)

		if ourErr == nil {
			if stdErr != nil {
				t.Fatalf("we accepted %q but stdlib rejected it: %v", data, stdErr)
			}
			if !bytes.Equal([]byte(out), []byte(viaStdlib)) {
				t.Fatalf("decode mismatch for %q: ours=%q stdlib=%q", data, []byte(out), viaStdlib)
			}
		}
	})
}
