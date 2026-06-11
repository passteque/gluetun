package auth

import (
	"fmt"
	"net/http"
	"slices"
)

func New(settings Settings, debugLogger DebugLogger) (
	middleware func(http.Handler) http.Handler,
	err error,
) {
	routeToRoles, err := settingsToLookupMap(settings)
	if err != nil {
		return nil, fmt.Errorf("converting settings to lookup maps: %w", err)
	}

	return func(handler http.Handler) http.Handler {
		return &authHandler{
			childHandler: handler,
			routeToRoles: routeToRoles,
			logger:       debugLogger,
		}
	}, nil
}

type authHandler struct {
	childHandler http.Handler
	routeToRoles map[string][]internalRole
	logger       DebugLogger
}

func (h *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	methods, ok := validRoutes[request.URL.Path]
	if !ok {
		h.logger.Debugf("url path %s is not a valid route", request.URL.Path)
		http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else if !slices.Contains(methods, request.Method) {
		h.logger.Debugf("method %s is not valid for url path %s", request.Method, request.URL.Path)
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	route := request.Method + " " + request.URL.Path
	roles := h.routeToRoles[route]
	if len(roles) == 0 {
		h.logger.Debugf("no authentication role defined for route %s", route)
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	responseHeader := make(http.Header, 0)
	for _, role := range roles {
		if !role.checker.isAuthorized(responseHeader, request) {
			continue
		}

		h.logger.Debugf("access to route %s authorized for role %s", route, role.name)
		h.childHandler.ServeHTTP(writer, request)
		return
	}

	// Flush out response headers if all roles failed to authenticate
	for headerKey, headerValues := range responseHeader {
		for _, headerValue := range headerValues {
			writer.Header().Add(headerKey, headerValue)
		}
	}

	allRoleNames := make([]string, len(roles))
	for i, role := range roles {
		allRoleNames[i] = role.name
	}
	h.logger.Debugf("access to route %s unauthorized after checking for roles %s",
		route, andStrings(allRoleNames))
	http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
