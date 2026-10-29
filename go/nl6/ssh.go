/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshIdleTimeoutDefault = 5 * time.Minute

// sshIdleTimeoutOverride replaces the default when positive. Only tests set
// it. It is atomic because connection goroutines read it.
var sshIdleTimeoutOverride atomic.Int64

// sshIdleTimeout returns the SSH idle deadline, 5 minutes unless a test
// overrides it.
func sshIdleTimeout() time.Duration {
	if v := sshIdleTimeoutOverride.Load(); v > 0 {
		return time.Duration(v)
	}
	return sshIdleTimeoutDefault
}

// newDeviceSSHConfig returns the SSH server config every device listener
// uses: the simulator credentials and the given host key.
func newDeviceSSHConfig(signer ssh.Signer) *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == USERNAME && string(pass) == PASSWORD {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	config.AddHostKey(signer)
	return config
}

// deviceListenTCP binds a TCP listener for d, inside its network namespace
// when it has one.
func deviceListenTCP(d *DeviceSimulator, addr string) (net.Listener, error) {
	if d.netNamespace != nil {
		return d.netNamespace.ListenTCPInNamespace("tcp", addr)
	}
	lc := net.ListenConfig{Control: setSocketBufferSize}
	return lc.Listen(context.Background(), "tcp", addr)
}

// SSH Server implementation
func (s *SSHServer) Start() error {
	// Use pre-generated host key if available, otherwise generate one
	var signer ssh.Signer
	if s.signer != nil {
		signer = s.signer
	} else {
		// Fallback: generate host key (should rarely happen)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

		signer, err = ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return err
		}
	}

	config := newDeviceSSHConfig(signer)

	addr := fmt.Sprintf("%s:%d", s.device.IP.String(), s.device.SSHPort)
	listener, err := deviceListenTCP(s.device, addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.config = config
	s.running.Store(true)

	go s.handleConnections()
	return nil
}

// Stop closes the listener and lets the accept loop exit. It is idempotent:
// a second call, or a call before Start, returns nil.
func (s *SSHServer) Stop() error {
	if !s.running.Swap(false) {
		return nil
	}
	return s.listener.Close()
}

func (s *SSHServer) handleConnections() {
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// The listener is gone (Stop, or a torn-down netns); nothing
				// to accept on, so leave instead of spinning on the error.
				return
			}
			if s.running.Load() {
				log.Printf("SSH server error accepting connection: %v", err)
			}
			continue
		}

		go s.handleConnection(conn)

	}
}

func (s *SSHServer) handleConnection(conn net.Conn) {
	// Set initial idle timeout — if no activity within this window, the connection closes
	conn.SetDeadline(time.Now().Add(sshIdleTimeout()))
	defer conn.Close()

	sshConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		// Don't log timeout-induced errors
		if !isTimeoutError(err) {
			log.Printf("SSH handshake error: %v", err)
		}
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Error accepting channel: %v", err)
			continue
		}

		go s.handleSession(channel, requests, conn)
	}
}

// isTimeoutError checks if an error is a network timeout
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, conn net.Conn) {
	defer channel.Close()

	shellReady := make(chan struct{}, 1)

	// Handle session requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req", "window-change":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
				select {
				case shellReady <- struct{}{}:
				default:
				}
			case "exec":
				req.Reply(true, nil)
				select {
				case shellReady <- struct{}{}:
				default:
				}
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Wait for shell or exec request before starting interactive session
	select {
	case <-shellReady:
	case <-time.After(10 * time.Second):
		return
	}

	// Send welcome message
	welcome := fmt.Sprintf("\r\nWelcome to %s\r\nDevice Simulator SSH Server\r\n\r\n", s.device.ID)
	channel.Write([]byte(welcome))

	s.interactiveLoop(channel, conn)
}

func (s *SSHServer) interactiveLoop(channel ssh.Channel, conn net.Conn) {
	buf := make([]byte, 1)
	var line []byte

	prompt := fmt.Sprintf("%s> ", s.device.ID)
	channel.Write([]byte(prompt))

	for {
		n, err := channel.Read(buf)
		if err != nil || n == 0 {
			break
		}

		// Reset idle timer on activity
		conn.SetDeadline(time.Now().Add(sshIdleTimeout()))

		b := buf[0]

		switch {
		case b == 3: // Ctrl-C
			channel.Write([]byte("^C\r\n"))
			line = nil
			channel.Write([]byte(prompt))
		case b == 4: // Ctrl-D
			channel.Write([]byte("\r\nGoodbye!\r\n"))
			return
		case b == 127 || b == 8: // Backspace / Delete
			if len(line) > 0 {
				line = line[:len(line)-1]
				channel.Write([]byte("\b \b"))
			}
		case b == '\r' || b == '\n':
			channel.Write([]byte("\r\n"))
			command := strings.TrimSpace(string(line))
			line = nil

			if command == "" {
				channel.Write([]byte(prompt))
				continue
			}

			if command == "exit" || command == "quit" {
				channel.Write([]byte("Goodbye!\r\n"))
				return
			}

			response := s.findCommandResponse(command)
			// Convert \n to \r\n for proper terminal display
			response = strings.ReplaceAll(response, "\n", "\r\n")
			channel.Write([]byte(response + "\r\n\r\n"))
			channel.Write([]byte(prompt))
		default:
			line = append(line, b)
			channel.Write([]byte{b}) // Echo character back
		}
	}
}

func (s *SSHServer) findCommandResponse(command string) string {
	// Safely access resources with read lock
	s.device.mu.RLock()
	defer s.device.mu.RUnlock()

	for _, resource := range s.device.resources.SSH {
		if strings.EqualFold(resource.Command, command) {
			return resource.Response
		}
	}
	return "Command not found"
}
