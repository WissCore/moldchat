// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cleanup_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps the cleanup tests in goleak so a Run loop that
// fails to exit on context cancel fails the suite.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
