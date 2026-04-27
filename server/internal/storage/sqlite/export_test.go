// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

// ParseSeedForTest exposes the unexported parseSeed function so the
// keys fuzz tests can hammer the parser directly. Going through
// LoadMasterSeed would force every fuzz iteration through t.Setenv,
// which itself rejects byte sequences (null bytes, "=" characters)
// that are otherwise interesting inputs to the parser.
func ParseSeedForTest(raw string) (MasterSeed, error) {
	return parseSeed(raw)
}
