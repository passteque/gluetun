package nftables

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/nftables"
)

var errRuleToDeleteNotFound = errors.New("rule not found for removal")

func (f *Firewall) deleteRule(conn *nftables.Conn, rule *nftables.Rule) error {
	for i, existing := range f.rules {
		if !reflect.DeepEqual(existing, rule) {
			continue
		}
		err := conn.DelRule(existing)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
		f.rules[i], f.rules[len(f.rules)-1] = f.rules[len(f.rules)-1], f.rules[i]
		f.rules = f.rules[:len(f.rules)-1]
		return nil
	}
	return fmt.Errorf("%w: %#v", errRuleToDeleteNotFound, rule)
}
