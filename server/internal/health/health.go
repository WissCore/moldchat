// Copyright 2026 Alan Wiss <alan@moldchat.com>
// Licensed under the GNU Affero General Public License v3.0 or later.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package health provides liveness HTTP handlers used by load balancers and
// orchestration to determine instance health.
package health

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Handler returns an http.Handler that responds with HTTP 200 and a small
// JSON document describing build status. It performs no checks against
// downstream dependencies — readiness is a separate concern.
func Handler() http.Handler {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		version = info.Main.Version
	}
	body := map[string]string{
		"status":  "ok",
		"version": version,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			slog.Default().Debug("healthz encode failed", "err", err.Error())
		}
	})
}
