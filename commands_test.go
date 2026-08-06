package main

import "testing"

// The knock port is open to the internet, so what it accepts is asserted rather
// than trusted to the client: everything that is not exactly `out` is refused.
func TestRunRemoteCommandAcceptsNothingButOut(t *testing.T) {
	refused := []string{
		"",
		"open",
		"clear",
		"close",
		"status",
		"list",
		"add 9.9.9.9",
		"remove 9.9.9.9",
		"out 9.9.9.9",
		"nuke",
		"OUT",
		" out",
	}

	for _, line := range refused {
		if _, err := runRemoteCommand(line, "1.2.3.4"); err == nil {
			t.Errorf("%q was accepted over the network", line)
		}
	}
}

// out takes no argument, so the address it removes can only ever be the one the
// connection came from.
func TestOutRemovesOnlyTheCaller(t *testing.T) {
	cmd := findCommand("out")
	if cmd == nil {
		t.Fatal("out command not registered")
	}

	if cmd.argCount() != 0 {
		t.Errorf("out takes %d arguments, it must take none", cmd.argCount())
	}

	if !cmd.remote {
		t.Error("out is local, but there is no caller IP on the server's own CLI")
	}

	if _, err := cmd.run(invocation{}); err == nil {
		t.Error("out ran without a caller IP")
	}
}

// Every other command administers the box and belongs on the box.
func TestOutIsTheOnlyRemoteCommand(t *testing.T) {
	for _, cmd := range commands {
		if cmd.remote && cmd.name != "out" {
			t.Errorf("%s is reachable over the knock port", cmd.name)
		}
	}
}
