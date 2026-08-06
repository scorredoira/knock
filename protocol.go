package main

// A knock and a remote command travel over the same port and the same SSH
// handshake, and are told apart by the user name the client authenticates as.
// The server has to know which of the two it is before it acts at all: a knock
// whitelists the caller on sight, a command must never do that.
const (
	knockUser   = "knock"
	commandUser = "command"

	commandChannel = "knock-command"
)

type commandRequest struct {
	Command string
}

type exitStatus struct {
	Status uint32
}
