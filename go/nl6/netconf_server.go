/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// netconfDeviceType is the one device type that serves NETCONF.
	netconfDeviceType = "cisco_catalyst_9500"
	// netconfKeepAlivePeriod replaces the SSH idle deadline once a
	// connection is authenticated. It only detects dead peers.
	netconfKeepAlivePeriod = 30 * time.Second
	// netconfSubsystemWait bounds how long a session channel may sit
	// without asking for the netconf subsystem. Port 22 uses the same value.
	netconfSubsystemWait = 10 * time.Second
)

// netconfServer is one device's NETCONF over SSH listener. It is stored as
// the device's netconfListener. Close stops the accept loop, closes every
// connection and session, and waits for all of their goroutines.
type netconfServer struct {
	net.Listener
	dev        *DeviceSimulator
	mgr        *SimulatorManager
	cfg        *ssh.ServerConfig
	reg        *netconfSessionRegistry
	ctx        context.Context
	cancel     context.CancelFunc
	sessionSeq atomic.Uint32

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closed    bool
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// startNetconfServer binds the device's NETCONF listener. It is a no-op
// unless the subsystem is active and the device is a catalyst 9500.
//
// Caller MUST hold d.mu.
func (d *DeviceSimulator) startNetconfServer(port int) error {
	if d == nil || d.netconfListener != nil {
		return nil
	}
	mgr := manager
	if mgr == nil || !mgr.netconfSubsystemActive.Load() || resourceDirName(d.resourceFile) != netconfDeviceType {
		return nil
	}
	if mgr.sharedSSHSigner == nil {
		return fmt.Errorf("no shared SSH host key available for NETCONF on %s", d.IP)
	}

	addr := fmt.Sprintf("%s:%d", d.IP.String(), port)
	var l net.Listener
	var err error
	if d.netNamespace != nil {
		l, err = d.netNamespace.ListenTCPInNamespace("tcp", addr)
	} else {
		lc := net.ListenConfig{Control: setSocketBufferSize}
		l, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to start NETCONF server on %s: %v", addr, err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == USERNAME && string(pass) == PASSWORD {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	cfg.AddHostKey(mgr.sharedSSHSigner)

	ctx, cancel := context.WithCancel(context.Background())
	srv := &netconfServer{
		Listener: l,
		dev:      d,
		mgr:      mgr,
		cfg:      cfg,
		reg:      newNetconfSessionRegistry(),
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[net.Conn]struct{}),
	}
	d.netconfListener = srv
	d.netconfSessions = srv.reg
	srv.wg.Add(1)
	go srv.acceptLoop()
	return nil
}

// stopNetconfServer closes the listener and every session. Idempotent.
//
// Caller MUST hold d.mu. Holding it across the wait is safe because no
// NETCONF session goroutine takes d.mu.
func (d *DeviceSimulator) stopNetconfServer() {
	if d == nil || d.netconfListener == nil {
		return
	}
	l := d.netconfListener
	d.netconfListener = nil
	d.netconfSessions = nil
	_ = l.Close()
}

// Close stops the server and waits for its goroutines.
func (s *netconfServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.Listener.Close()
		s.mu.Lock()
		s.closed = true
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		s.reg.closeAll()
		s.wg.Wait()
	})
	return err
}

func (s *netconfServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("NETCONF server error accepting connection on %s: %v", s.dev.IP, err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		go s.serveConn(conn)
	}
}

// track registers conn and counts its goroutine. It refuses once Close ran,
// so wg.Add never races wg.Wait.
func (s *netconfServer) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *netconfServer) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *netconfServer) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer s.untrack(conn)
	defer conn.Close()

	// The SSH idle deadline bounds the handshake only. A NETCONF session
	// sits quiet between notifications for hours, so the deadline is
	// cleared once the client is in and TCP keepalive takes over.
	_ = conn.SetDeadline(time.Now().Add(sshIdleTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	_ = conn.SetDeadline(time.Time{})
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(netconfKeepAlivePeriod)
	}
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		// This goroutine is still counted, so the counter is positive and
		// Add may run alongside Wait.
		s.wg.Add(1)
		go s.serveChannel(ch, creqs)
	}
}

// serveChannel accepts only the netconf subsystem request. Every other
// request, shell and exec included, is refused.
func (s *netconfServer) serveChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer s.wg.Done()
	defer ch.Close()

	start := make(chan struct{})
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		started := false
		for req := range reqs {
			ok := !started && req.Type == "subsystem" && netconfSubsystemName(req.Payload) == "netconf"
			_ = req.Reply(ok, nil)
			if ok {
				started = true
				close(start)
			}
		}
	}()

	select {
	case <-start:
	case <-gone:
		return
	case <-s.ctx.Done():
		return
	case <-time.After(netconfSubsystemWait):
		return
	}

	atomic.AddUint64(&s.mgr.netconfSessionsOpened, 1)
	sess := newIOSXENetconfSession(s.sessionSeq.Add(1), s.dev, ch, s.reg)
	if err := sess.Serve(s.ctx); err != nil {
		log.Printf("NETCONF session on %s ended: %v", s.dev.IP, err)
	}
}

// netconfSubsystemName decodes the SSH string in a subsystem request payload.
func netconfSubsystemName(payload []byte) string {
	var p struct{ Name string }
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return p.Name
}
