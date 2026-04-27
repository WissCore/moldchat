// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps the v1 HTTP-handler tests in goleak so any
// httptest server that fails to close cleanly fails the suite.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
