package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAPIServerStopClosesHTTPServer(t *testing.T) {
	originalListen := apiListenTCP
	originalNewServer := apiNewHTTPServer
	t.Cleanup(func() {
		apiListenTCP = originalListen
		apiNewHTTPServer = originalNewServer
	})

	listener := &stubListener{}
	server := newBlockingAPIServer()
	apiListenTCP = func(device *DeviceSimulator, addr string) (net.Listener, error) {
		return listener, nil
	}
	apiNewHTTPServer = func(handler http.Handler) apiHTTPServer {
		return server
	}

	device := &DeviceSimulator{
		IP:      net.IPv4(127, 0, 0, 1),
		APIPort: 8443,
		resources: &DeviceResources{
			API: []APIResource{
				{
					Method:   "GET",
					Path:     "/health",
					Response: map[string]string{"status": "ok"},
				},
			},
		},
	}
	apiServer := &APIServer{
		device:        device,
		sharedTLSCert: &tls.Certificate{},
	}

	if err := apiServer.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	<-server.serveCalled

	if err := apiServer.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	select {
	case <-server.closeCalled:
	default:
		t.Fatal("Stop() did not close the HTTP server")
	}
}

// TestAPIServerStartClosesListenerWhenTLSCertMissing covers the Start()
// error path when sharedTLSCert is nil: the listener must be closed so
// the bound socket (and its namespace veth, if source-per-device is on)
// is not orphaned on the way out.
func TestAPIServerStartClosesListenerWhenTLSCertMissing(t *testing.T) {
	originalListen := apiListenTCP
	t.Cleanup(func() { apiListenTCP = originalListen })

	listener := &stubListener{}
	apiListenTCP = func(device *DeviceSimulator, addr string) (net.Listener, error) {
		return listener, nil
	}

	device := &DeviceSimulator{
		IP:      net.IPv4(127, 0, 0, 1),
		APIPort: 8443,
		resources: &DeviceResources{
			API: []APIResource{
				{
					Method:   "GET",
					Path:     "/health",
					Response: map[string]string{"status": "ok"},
				},
			},
		},
	}
	server := &APIServer{device: device}

	if err := server.Start(); err == nil {
		t.Fatal("Start() error = nil, want missing TLS certificate error")
	}

	if !listener.closed {
		t.Fatal("listener.Close() was not called on TLS setup failure")
	}
}

type blockingAPIServer struct {
	serveCalled chan struct{}
	closeCalled chan struct{}
	done        chan struct{}
}

func newBlockingAPIServer() *blockingAPIServer {
	return &blockingAPIServer{
		serveCalled: make(chan struct{}),
		closeCalled: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

func (s *blockingAPIServer) Serve(net.Listener) error {
	close(s.serveCalled)
	<-s.done
	return http.ErrServerClosed
}

func (s *blockingAPIServer) Close() error {
	close(s.closeCalled)
	close(s.done)
	return nil
}

// stubListener is a minimal net.Listener used by both tests. `closed` is
// flipped by Close() so TestAPIServerStartClosesListenerWhenTLSCertMissing
// can assert the error path actually closed the socket.
type stubListener struct {
	closed bool
}

func (l *stubListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (l *stubListener) Close() error {
	l.closed = true
	return nil
}

func (l *stubListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
}

func (l *stubListener) SetDeadline(time.Time) error {
	return nil
}
