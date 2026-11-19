// Package testuser provides the users a test needs to assert the file
// permission checks: it runs the cases needing a regular user when the test
// runs as root, and gives an owner no capability exempts from these checks.
package testuser
