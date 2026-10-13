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

package systemhealth

import (
	"context"
	"fmt"
)

// AutomationEngineReader reports whether the Security Automation
// trigger engine exists in the running process, and whether any rule
// is enabled.
//
// Satisfied by a thin adapter over automation.GetManager() in the
// wiring file; the interface keeps this package from importing the
// automation package, as with every other check here.
type AutomationEngineReader interface {
	// Running is false when wireAutomation failed at boot.
	Running() bool
	// RulesEnabled is the number of enabled rules in the stored set.
	// Zero is the normal opt-out state.
	RulesEnabled() int
}

// AutomationCheck reports a Security Automation rule set that nothing
// is evaluating (v2.72).
//
// Rules are saved and audited whether the engine runs or not, which is
// the right call: they take effect at the next boot and refusing the
// write would lose the operator's work. But wireAutomation failing at
// boot logs one WARN line and Arenet keeps serving, so an operator
// could have enabled rules, seen them saved, seen them in the audit
// trail, and had nothing anywhere tell them no bans were being pushed.
//
// Classification, matching the posture of CrowdSecCheck next door:
//
//   - healthy: the engine is running, or no rule is enabled (the engine
//     being down then changes nothing);
//   - degraded: rules are enabled and the engine is not running;
//   - unhealthy: never. Automation is optional and the data plane is
//     unaffected — it is a degraded security posture, not a broken
//     system.
type AutomationCheck struct {
	Engine AutomationEngineReader
}

// Name implements ComponentCheck.
func (c *AutomationCheck) Name() string { return "automation" }

// Check implements ComponentCheck.
func (c *AutomationCheck) Check(_ context.Context) ComponentStatus {
	if c.Engine == nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "automation not wired (degraded mode)",
		}
	}
	if c.Engine.Running() {
		return ComponentStatus{Status: StatusHealthy, Message: "trigger engine running"}
	}
	// Not running. Whether that matters depends on whether the operator
	// is relying on it: an install that never enabled a rule is not
	// degraded by an engine it does not use.
	if n := c.Engine.RulesEnabled(); n > 0 {
		return ComponentStatus{
			Status: StatusDegraded,
			Message: fmt.Sprintf(
				"trigger engine not running: %s enabled but nothing is evaluating them",
				pluralRules(n)),
		}
	}
	return ComponentStatus{Status: StatusHealthy, Message: "trigger engine disabled, no rule enabled"}
}

// pluralRules keeps the message readable for one rule.
func pluralRules(n int) string {
	if n == 1 {
		return "1 rule"
	}
	return fmt.Sprintf("%d rules", n)
}
