// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
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

// Package web bundles the SvelteKit production build into the Arenet
// binary via go:embed.
package web

import (
	"embed"
	"io/fs"
)

// The "all:" prefix is required because SvelteKit emits files starting with
// "_" (e.g. _app/) which the default //go:embed rules skip. The
// build/.gitkeep file guarantees this directory exists at compile time even
// before the first `npm run build`.
//
//go:embed all:frontend/build
var staticFS embed.FS

// StaticFS returns the embedded SvelteKit build directory rooted at
// frontend/build so that http.FileServer serves it from /.
func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFS, "frontend/build")
}
