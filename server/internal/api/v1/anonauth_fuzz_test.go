// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1

import "testing"

// FuzzParseAnonauthToken probes the token-header parser against
// arbitrary inputs. The parser must never panic and must always
// either return a valid (input, mac) split with the expected mac
// length or an error; anything else turns the parser into a denial-
// of-service surface.
func FuzzParseAnonauthToken(f *testing.F) {
	f.Add("")
	f.Add("AAAA")
	f.Add("not!base64!")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(t *testing.T, header string) {
		input, mac, err := parseAnonauthToken(header)
		if err != nil {
			if input != nil || mac != nil {
				t.Fatalf("error path returned non-nil slices")
			}
			return
		}
		const macLen = 64
		if len(mac) != macLen {
			t.Fatalf("mac length %d, want %d", len(mac), macLen)
		}
		if len(input) == 0 {
			t.Fatalf("non-error parse returned empty input")
		}
	})
}
