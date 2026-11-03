/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// netconfKeepAlivePeriod replaces the SSH idle deadline once a
	// connection is authenticated. It only detects dead peers.
	netconfKeepAlivePeriod = 30 * time.Second
	// netconfSubsystemWait bounds how long a session channel may sit
	// without asking for the netconf subsystem. Port 22 uses the same value.
	netconfSubsystemWait = 10 * time.Second
)

// netconfServer is one device's NETCONF listener, over SSH (stored as the
// device's netconfListener) or over TLS (netconfTLSListener, tlsCfg set).
// Close stops the accept loop, closes every connection and session of this
// listener, and waits for all of their goroutines.
type netconfServer struct {
	net.Listener
	dev    *DeviceSimulator
	mgr    *SimulatorManager
	cfg    *ssh.ServerConfig // SSH only
	tlsCfg *tls.Config       // TLS only, nil on the SSH listener
	dia    netconfDialect
	reg    *netconfSessionRegistry
	ctx    context.Context
	cancel context.CancelFunc
	// keepAlive, when set, makes the device send an SSH keepalive request at
	// this interval and close the connection after keepAliveMisses requests
	// in a row get no reply. Only call home sets it; listeners rely on TCP
	// keepalive.
	keepAlive       time.Duration
	keepAliveMisses int
	// handshakeTimeout, when set, bounds the SSH handshake instead of the
	// SSH idle timeout. onHandshake, when set, runs once the handshake
	// succeeds. Only call home sets them.
	handshakeTimeout time.Duration
	onHandshake      func()

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closed    bool
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// startNetconfServer binds the device's NETCONF listener. It is the one
// place that decides whether a device serves NETCONF: it is a no-op unless
// the manager exists, the subsystem is active and the device's profile has
// a NETCONF dialect served over SSH.
//
// Caller MUST hold d.mu.
func (d *DeviceSimulator) startNetconfServer() error {
	if d == nil || d.netconfListener != nil {
		return nil
	}
	mgr := manager
	if mgr == nil || !mgr.netconfSubsystemActive.Load() {
		return nil
	}
	dia, ok := netconfDialectFor(d)
	if !ok || !dia.SSH {
		return nil
	}
	if mgr.sharedSSHSigner == nil {
		return fmt.Errorf("no shared SSH host key available for NETCONF on %s", d.IP)
	}

	addr := fmt.Sprintf("%s:%d", d.IP.String(), mgr.netconfPort)
	l, err := deviceListenTCP(d, addr)
	if err != nil {
		return fmt.Errorf("failed to start NETCONF server on %s: %v", addr, err)
	}

	srv := d.newNetconfServer(l, mgr, dia)
	srv.cfg = newDeviceSSHConfig(mgr.sharedSSHSigner)
	d.netconfListener = srv
	srv.wg.Add(1)
	go srv.acceptLoop()
	return nil
}

// newNetconfServer builds a listener's server on l. The device's session
// registry is created by the first listener and shared by the second, so
// session ids, kill-session and the state-change dispatcher span both
// transports.
//
// Caller MUST hold d.mu.
func (d *DeviceSimulator) newNetconfServer(l net.Listener, mgr *SimulatorManager, dia netconfDialect) *netconfServer {
	if d.netconfSessions == nil {
		d.netconfSessions = newNetconfSessionRegistry()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &netconfServer{
		Listener: l,
		dev:      d,
		mgr:      mgr,
		dia:      dia,
		reg:      d.netconfSessions,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[net.Conn]struct{}),
	}
}

// stopNetconfServer closes the device's NETCONF listeners, SSH and TLS, and
// every session. It is the one NETCONF stop for a device. Idempotent.
//
// Caller MUST hold d.mu. Holding it across the wait is safe because no
// NETCONF session goroutine takes d.mu.
func (d *DeviceSimulator) stopNetconfServer() {
	if d == nil {
		return
	}
	// Call home first: its server shares the session registry closed below.
	d.stopNetconfCallHome()
	reg := d.netconfSessions
	listeners := []net.Listener{d.netconfListener, d.netconfTLSListener}
	d.netconfListener, d.netconfTLSListener, d.netconfSessions = nil, nil, nil
	if reg != nil {
		reg.closeAll()
	}
	for _, l := range listeners {
		if l != nil {
			_ = l.Close()
		}
	}
}

// Close stops the server and waits for its goroutines. Cancelling ctx ends
// this listener's sessions; the sessions of the device's other listener are
// left alone.
func (s *netconfServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		// A call-home server has no listener, only the connection it dialed.
		if s.Listener != nil {
			err = s.Listener.Close()
		}
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

	if s.tlsCfg != nil {
		s.serveTLS(conn)
		return
	}

	// The SSH idle deadline bounds the handshake and the wait for the
	// netconf subsystem. A NETCONF session sits quiet between notifications
	// for hours, so dispatch clears the deadline once the session starts
	// and TCP keepalive takes over.
	handshake := sshIdleTimeout()
	if s.handshakeTimeout > 0 {
		handshake = s.handshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(handshake))
	sc, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	if s.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(sshIdleTimeout()))
	}
	if s.onHandshake != nil {
		s.onHandshake()
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(netconfKeepAlivePeriod)
	}
	if s.keepAlive > 0 {
		stop := make(chan struct{})
		defer close(stop)
		// This goroutine is counted, so Add may run alongside Wait.
		s.wg.Add(1)
		go s.sshKeepAlive(conn, sc, stop)
	}
	s.dispatch(conn, sc, chans, reqs)
}

// sshKeepAlive sends a keepalive request every s.keepAlive and closes conn
// after s.keepAliveMisses ticks in a row find the request still unanswered.
// Any reply counts, a refusal too: a client that refuses an unknown request
// is alive. It ends when stop closes or the connection fails.
//
// Junos sends one keepalive per interval even while earlier ones are
// unanswered. x/crypto/ssh holds a lock in SendRequest until the reply, so
// only one global request can be in flight per connection, and nl6 sends the
// next one only after the reply. The close comes at the same time either way.
func (s *netconfServer) sshKeepAlive(conn net.Conn, sc ssh.Conn, stop <-chan struct{}) {
	defer s.wg.Done()
	t := time.NewTicker(s.keepAlive)
	defer t.Stop()
	var replied chan error // nil while no request is outstanding
	misses := 0
	for {
		select {
		case <-stop:
			return
		case err := <-replied:
			if err != nil {
				return
			}
			replied, misses = nil, 0
		case <-t.C:
			if replied != nil {
				misses++
				if misses >= s.keepAliveMisses {
					_ = conn.Close()
					return
				}
				continue
			}
			replied = make(chan error, 1)
			go func(ch chan<- error) {
				_, _, err := sc.SendRequest("keepalive@openssh.com", true, nil)
				ch <- err
			}(replied)
		}
	}
}

// dispatch is the connection's one control loop. It refuses global requests,
// accepts session channels and answers their requests, so no goroutine per
// request stream is needed. Only the netconf subsystem is accepted, once per
// channel. Every other request, shell and exec included, is refused, also
// after the session started. A channel that does not ask for the subsystem
// within netconfSubsystemWait is closed.
//
// One NETCONF session runs per connection, as on IOS XE. A session channel
// that opens while another still waits for its subsystem replaces it. One
// that opens after the session started is refused.
func (s *netconfServer) dispatch(conn net.Conn, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	var (
		pending     ssh.Channel // accepted, waiting for the subsystem
		pendingReqs <-chan *ssh.Request
		activeReqs  <-chan *ssh.Request // the running session's channel
		started     bool
	)
	wait := time.NewTimer(netconfSubsystemWait)
	wait.Stop()
	defer wait.Stop()
	// dropPending closes the pending channel. A local Close only sends
	// channel-close: its request stream stays open until the peer answers,
	// and the SSH mux blocks on a full stream. So a stream that is still
	// open is drained until it closes, or one client could stall the mux,
	// and with it Close.
	dropPending := func() {
		if pending != nil {
			_ = pending.Close()
		}
		if pendingReqs != nil {
			s.wg.Add(1)
			go s.refuseAll(pendingReqs)
		}
		pending, pendingReqs = nil, nil
		wait.Stop()
	}
	defer dropPending()

	for {
		select {
		case nc, ok := <-chans:
			if !ok {
				return
			}
			if nc.ChannelType() != "session" {
				_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			if started {
				_ = nc.Reject(ssh.Prohibited, "one NETCONF session per connection")
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			dropPending()
			pending, pendingReqs = ch, creqs
			wait.Reset(netconfSubsystemWait)
		case req, ok := <-reqs:
			if !ok {
				reqs = nil
				continue
			}
			_ = req.Reply(false, nil)
		case req, ok := <-activeReqs:
			if !ok {
				activeReqs = nil
				continue
			}
			_ = req.Reply(false, nil)
		case req, ok := <-pendingReqs:
			if !ok {
				pendingReqs = nil
				dropPending()
				continue
			}
			if req.Type != "subsystem" || netconfSubsystemName(req.Payload) != "netconf" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			ch := pending
			activeReqs, started = pendingReqs, true
			pending, pendingReqs = nil, nil
			wait.Stop()
			_ = conn.SetDeadline(time.Time{})
			// This goroutine is still counted, so the counter is positive and
			// Add may run alongside Wait.
			s.wg.Add(1)
			go s.serveChannel(sc, ch)
		case <-wait.C:
			dropPending()
		}
	}
}

// refuseAll refuses every request on reqs until the stream closes. It runs
// only for a channel dropped before its session started, so an idle session
// costs no goroutine here. The stream closes when the peer closes the
// channel or the connection ends.
func (s *netconfServer) refuseAll(reqs <-chan *ssh.Request) {
	defer s.wg.Done()
	for req := range reqs {
		_ = req.Reply(false, nil)
	}
}

// serveChannel runs one NETCONF session. When it ends, by close-session,
// kill-session or EOF, the whole SSH connection is closed: IOS XE runs one
// NETCONF session per connection.
func (s *netconfServer) serveChannel(sc ssh.Conn, ch ssh.Channel) {
	defer s.wg.Done()
	defer ch.Close()
	if s.ctx.Err() != nil {
		return
	}
	sess := s.dia.NewSession(s.reg.sessionSeq.Add(1), s.dev, ch, s.reg, USERNAME)
	// kill-session closes the victim's whole connection, not only its
	// channel.
	sess.conn = sc
	if err := sess.Serve(s.ctx); err != nil {
		log.Printf("NETCONF session on %s ended: %v", s.dev.IP, err)
	}
	_ = sc.Close()
	// The connection is down, so a writer blocked on the channel window
	// returns. Waiting here keeps Close from returning while the session's
	// listener or writer still runs.
	sess.waitEvents()
}

// netconfSubsystemName decodes the SSH string in a subsystem request payload.
func netconfSubsystemName(payload []byte) string {
	var p struct{ Name string }
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return p.Name
}
