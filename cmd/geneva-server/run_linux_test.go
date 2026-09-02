//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRuntimeExitErrorDistinguishesFatalFromSignalShutdown(t *testing.T) {
	fatal := make(chan error, 1)
	serve := make(chan error, 1)
	fatal <- errors.New("unconfirmed steering disable")
	if err := runtimeExitError(context.Canceled, fatal, serve); err == nil || !strings.Contains(err.Error(), "unconfirmed steering disable") {
		t.Fatalf("fatal cancellation exit = %v", err)
	}
	if err := runtimeExitError(context.Canceled, make(chan error), make(chan error)); err != nil {
		t.Fatalf("ordinary signal cancellation exit = %v", err)
	}
}

func TestServiceRestartsIntegrityFailureExit(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/geneva-server.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "Restart=on-failure") {
		t.Fatal("service will not restart a nonzero integrity-fatal exit")
	}
}
