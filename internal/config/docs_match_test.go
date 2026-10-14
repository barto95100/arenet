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

package config

import (
	"os"
	"strings"
	"testing"
)

// The admin bind is documented in three places and tested in one.
//
// v2.71.0 moved the default from ":8001" to "127.0.0.1:8001".
// TestDefault_AdminBindsLoopbackPerD6 has guarded the new value from
// the day it landed, and TestFlagOverridesEnv has guarded the flag
// layer since long before that. Neither noticed that
// docs/operations/env-vars.md kept telling the operator the default
// was ":8001" — "binds all interfaces" — on the same page that calls
// this variable "the security boundary for the admin surface". The
// code was right, three documents were wrong, and the only thing that
// could have caught it was a reader.
//
// So the gap is not a missing assertion about behaviour; it is that
// nothing crosses from the code to the prose. These two tests do. They
// are deliberately narrow: they check the facts the docs *assert*
// about this package and about the image, not their wording.
//
// Related class: twelve file:line citations in these same docs went
// stale on the Caddy 2.11.3 → 2.11.4 bump with nothing complaining.

// envVarsDoc is the operator page that documents ARENET_ADMIN_BIND.
const envVarsDoc = "../../docs/operations/env-vars.md"

// dockerfilePath holds the CMD that overrides the loopback default
// inside the container.
const dockerfilePath = "../../Dockerfile"

// TestDocumentedAdminBindDefaultMatchesCode fails when the default in
// the operator docs drifts from the one the binary actually uses.
//
// It reads the "- **Default**:" bullet of the ARENET_ADMIN_BIND
// section and requires NewDefault().AdminPort to appear in it. A
// reworded bullet is fine; a bullet naming a different address is not.
func TestDocumentedAdminBindDefaultMatchesCode(t *testing.T) {
	want := NewDefault().AdminPort

	bullet := defaultBulletFor(t, "ARENET_ADMIN_BIND")
	if !strings.Contains(bullet, want) {
		t.Errorf("docs/operations/env-vars.md documents a different admin bind default\n"+
			"  code (NewDefault().AdminPort): %q\n"+
			"  doc bullet:                    %s\n"+
			"The doc is what an operator hardens from. Update the bullet.",
			want, bullet)
	}

	// The old value is the one that was wrong for the whole v2 line,
	// and it is a substring of nothing in the current default, so
	// naming it outside a historical clause is almost certainly a
	// regression of the same bug.
	if strings.Contains(bullet, `\`+"`:8001`") {
		t.Errorf("the Default bullet names `:8001` as the default again:\n  %s", bullet)
	}
}

// TestDockerfileStillOverridesTheLoopbackDefault guards the premise of
// the Docker note in env-vars.md, hardening.md and docker-compose.yml:
// that the image's CMD passes --admin-port, so ARENET_ADMIN_BIND has no
// effect there.
//
// If the flag is dropped from the image, those three documents become
// wrong AND a published-port mapping stops reaching the admin API —
// the container would bind loopback while Docker forwards to eth0,
// which is why the flag is there (see the NewDefault doc comment).
func TestDockerfileStillOverridesTheLoopbackDefault(t *testing.T) {
	raw, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read %s: %v", dockerfilePath, err)
	}

	var cmd string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "CMD ") {
			cmd = strings.TrimSpace(line)
		}
	}
	if cmd == "" {
		t.Fatalf("no CMD instruction found in %s", dockerfilePath)
	}
	if !strings.Contains(cmd, "--admin-port") {
		t.Errorf("the image CMD no longer passes --admin-port:\n  %s\n"+
			"Three documents state that it does, and a published port needs it: "+
			"without the flag the container binds %q and -p 127.0.0.1:8001:8001 "+
			"cannot reach it. Fix the image or fix the docs.",
			cmd, NewDefault().AdminPort)
	}
}

// defaultBulletFor returns the "- **Default**:" bullet belonging to the
// given variable's section, joined onto one line.
//
// The bullet wraps across source lines, so everything up to the next
// bullet is collected. Failing to find the section is fatal rather than
// skipped: a renamed heading is itself a doc change worth noticing.
func defaultBulletFor(t *testing.T, envVar string) string {
	t.Helper()

	raw, err := os.ReadFile(envVarsDoc)
	if err != nil {
		t.Fatalf("read %s: %v", envVarsDoc, err)
	}

	heading := "### `" + envVar + "`"
	_, after, found := strings.Cut(string(raw), heading)
	if !found {
		t.Fatalf("%s has no %q section", envVarsDoc, heading)
	}
	// Stop at the next variable so a later section's Default bullet
	// can never be mistaken for this one's.
	if next := strings.Index(after, "\n### "); next != -1 {
		after = after[:next]
	}

	_, bullet, found := strings.Cut(after, "- **Default**:")
	if !found {
		t.Fatalf("the %s section has no \"- **Default**:\" bullet", envVar)
	}
	if next := strings.Index(bullet, "\n- "); next != -1 {
		bullet = bullet[:next]
	}
	return strings.Join(strings.Fields(bullet), " ")
}
