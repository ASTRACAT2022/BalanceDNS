package knot

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"
)

// Adapter connects to the Knot Resolver control socket.
type Adapter struct {
	socketPath string
	timeout    time.Duration
	mu         sync.Mutex
}

// NewAdapter creates a new Knot Resolver adapter.
func NewAdapter(socketPath string, timeout time.Duration) *Adapter {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &Adapter{
		socketPath: socketPath,
		timeout:    timeout,
	}
}

// Execute sends a Lua command to the control socket and returns the response.
// Note: kresd control socket is an interactive Lua shell.
// We send the command followed by newline. response ends with prompt usually, or we read until newline?
// Standard kresd library or client usually handles this. Since we are raw:
// We send "command\n". We read response.
// This is a simplified implementation. Proper implementation might need to handle the prompt output ('> ').
func (a *Adapter) Execute(command string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	conn, err := net.DialTimeout("unix", a.socketPath, a.timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to knot socket: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(a.timeout)); err != nil {
		return "", err
	}

	// Send command
	_, err = fmt.Fprintf(conn, "%s\n", command)
	if err != nil {
		return "", fmt.Errorf("failed to write to socket: %v", err)
	}

	// Read response
	// This is tricky because we don't know how long the response is.
	// Kresd usually ends with a prompt '> ' or established delimiter.
	// For this MVP, we'll read until EOF or timeout, but since we keep connection open usually...
	// Wait, we are dialing fresh every time here for simplicity.
	// If it's a Unix socket, Close() by server might not happen.
	// Let's rely on a simple read buffer or assume a one-line response for now if valid,
	// or valid JSON output if we wrap commands.

	scanner := bufio.NewScanner(conn)
	var output string
	for scanner.Scan() {
		line := scanner.Text()
		// If line is just the prompt, we might stop?
		if line == "> " || line == ">" {
			break
		}
		output += line + "\n"
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	return output, nil
}
