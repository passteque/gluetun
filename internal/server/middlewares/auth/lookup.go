package auth

import (
	"fmt"
)

type internalRole struct {
	name    string
	checker authorizationChecker
}

func settingsToLookupMap(settings Settings) (routeToRoles map[string][]internalRole, err error) {
	routeToRoles = make(map[string][]internalRole)
	for _, role := range settings.Roles {
		var checker authorizationChecker
		switch role.Auth {
		case AuthNone:
			checker = newNoneMethod()
		case AuthAPIKey:
			checker = newAPIKeyMethod(role.APIKey)
		case AuthBasic:
			checker = newBasicAuthMethod(role.Username, role.Password)
		default:
			return nil, fmt.Errorf("authentication method not supported: %s", role.Auth)
		}

		iRole := internalRole{
			name:    role.Name,
			checker: checker,
		}
		for _, route := range role.Routes {
			checkerExists := false
			for _, role := range routeToRoles[route] {
				if role.checker.equal(iRole.checker) {
					checkerExists = true
					break
				}
			}
			if checkerExists {
				// even if the role name is different, if the checker is the same, skip it.
				continue
			}
			routeToRoles[route] = append(routeToRoles[route], iRole)
		}
	}
	return routeToRoles, nil
}
