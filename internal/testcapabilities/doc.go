// Package testcapabilities drops the capabilities of the thread running a
// test, to reproduce the file permission checks of a container started
// without them, for example with cap_drop: ALL.
package testcapabilities
