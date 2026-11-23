// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package backup

import (
	"context"

	"github.com/barto95100/arenet/internal/allowlist"
)

// AllowlistSource reads the AreNET allowlists for export (#372). It is a
// local interface so the backup package stays decoupled from the concrete
// allowlist store (mirrors Storer / UserStorer). Satisfied by
// *allowlist.Store.
type AllowlistSource interface {
	List(ctx context.Context) ([]allowlist.Allowlist, error)
}

// AllowlistSink replaces the AreNET allowlists on restore (#372). The whole
// set is replaced transactionally. Satisfied by *allowlist.Store.
type AllowlistSink interface {
	ReplaceAll(ctx context.Context, lists []allowlist.Allowlist) error
}

// firstAllowlistSource / firstAllowlistSink unwrap the variadic optional
// dependency: Export/Import take `...AllowlistSource` / `...AllowlistSink`
// so existing callers (and tests) stay unchanged, and a caller that cares
// about allowlists passes exactly one. A nil or absent value means "no
// allowlists in this snapshot" (the pre-#372 behaviour).
func firstAllowlistSource(srcs []AllowlistSource) AllowlistSource {
	if len(srcs) > 0 && srcs[0] != nil {
		return srcs[0]
	}
	return nil
}

func firstAllowlistSink(sinks []AllowlistSink) AllowlistSink {
	if len(sinks) > 0 && sinks[0] != nil {
		return sinks[0]
	}
	return nil
}
