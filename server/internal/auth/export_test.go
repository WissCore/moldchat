// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import "time"

// SetClockForTest replaces the issuer's clock. Test-only.
func SetClockForTest(i *Issuer, clock func() time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.now = clock
}
