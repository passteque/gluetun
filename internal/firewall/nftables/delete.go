//go:build linux

package nftables

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/nftables"
)

var errRuleToDeleteNotFound = errors.New("rule not found for removal")

// deleteRule queues the deletion of the given rule on the given connection.
// The rule must be one of the tracked rules, otherwise an error wrapping
// [errRuleToDeleteNotFound] is returned.
//
// Note that rules added with [conn.AddRule] do not have a valid handle, as the
// library does not parse the netlink echo, so the rule actually present in the
// kernel is fetched with [conn.GetRules] and matched by its expressions to
// obtain the handle to use for deletion.
//
// The rule stays tracked; the caller must flush the connection and, on
// success, call [Firewall.untrackRule].
func (f *Firewall) deleteRule(conn conn, rule *nftables.Rule) error {
	if f.trackedRuleIndex(rule) == -1 {
		return fmt.Errorf("%w: %#v", errRuleToDeleteNotFound, rule)
	}

	rules, err := conn.GetRules(rule.Table, rule.Chain)
	if err != nil {
		return fmt.Errorf("fetching rules for deletion: %w", err)
	}

	for _, existing := range rules {
		if !reflect.DeepEqual(existing.Exprs, rule.Exprs) {
			continue
		}
		if err := conn.DelRule(existing); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("%w: %#v", errRuleToDeleteNotFound, rule)
}

// trackedRuleIndex returns the index of the first tracked rule with the same
// expressions as the given rule, or -1 if the rule is not tracked.
func (f *Firewall) trackedRuleIndex(rule *nftables.Rule) int {
	for i, tracked := range f.rules {
		if reflect.DeepEqual(tracked.Exprs, rule.Exprs) {
			return i
		}
	}
	return -1
}

// removeTrackedRule removes the tracked rule at the given index.
func (f *Firewall) removeTrackedRule(index int) {
	f.rules[index], f.rules[len(f.rules)-1] = f.rules[len(f.rules)-1], f.rules[index]
	f.rules = f.rules[:len(f.rules)-1]
}

// untrackRule removes the given rule from the tracked rules, if it is tracked.
func (f *Firewall) untrackRule(rule *nftables.Rule) {
	if index := f.trackedRuleIndex(rule); index != -1 {
		f.removeTrackedRule(index)
	}
}
