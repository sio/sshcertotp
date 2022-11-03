//
// Integration tests
//

package main

import (
	"testing"
	"time"
)

type testServer struct {
	ca *certServer
	s  chan bool
}

func (ts *testServer) Start(config *certServerConfig) error {
	if config == nil {
		config = &certServerConfig{
			Address:  "127.0.0.1:20000",
			CAPath:   "demo/keys/ca-insecure",
			Validity: 1 * time.Hour,
		}
	}

	ts.s = make(chan bool)
	var err error
	ts.ca, err = NewCertServer(config)
	if err != nil {
		return err
	}
	go ts.ca.run(ts.s)
	return nil
}

func (ts *testServer) Stop() {
	ts.s <- true
}

func TestStartStop(t *testing.T) {
	var server testServer
	var err error
	err = server.Start(nil)
	if err != nil {
		t.Fatalf("test server startup error: %v", err)
	}
	server.Stop()
}
