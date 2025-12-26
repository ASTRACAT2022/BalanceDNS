package resolver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrTimeout    = errors.New("i/o timeout")
	ErrDial       = errors.New("failed to dial")
	ErrPoolClosed = errors.New("connection pool closed")
)

const maxConnectionsPerHost = 10

// DNSClient is a custom DNS client with connection pooling.
type DNSClient struct {
	tcpPools  map[string]chan *dns.Conn
	mu        sync.Mutex
	timeout   time.Duration
	udpClient *dns.Client
	closed    bool
}

// NewDNSClient creates a new DNSClient.
func NewDNSClient(timeout time.Duration) *DNSClient {
	return &DNSClient{
		tcpPools: make(map[string]chan *dns.Conn),
		timeout:  timeout,
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
			UDPSize: 4096,
		},
	}
}

// getTcpConn gets a TCP connection from the pool or creates a new one.
func (c *DNSClient) getTcpConn(server string) (*dns.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrPoolClosed
	}

	pool, ok := c.tcpPools[server]
	if !ok {
		pool = make(chan *dns.Conn, maxConnectionsPerHost)
		c.tcpPools[server] = pool
	}
	c.mu.Unlock()

	select {
	case conn := <-pool:
		if conn == nil {
			// The pool was closed and drained.
			return nil, ErrPoolClosed
		}
		// Got a connection from the pool.
		return conn, nil
	default:
		// Pool is empty, create a new connection.
		return dns.DialTimeout("tcp", server, c.timeout)
	}
}

// putTcpConn returns a TCP connection to the pool.
func (c *DNSClient) putTcpConn(conn *dns.Conn) {
	if conn == nil {
		return
	}

	server := conn.RemoteAddr().String()

	c.mu.Lock()
	if c.closed {
		conn.Close()
		c.mu.Unlock()
		return
	}
	pool, ok := c.tcpPools[server]
	c.mu.Unlock()

	if !ok {
		// Pool doesn't exist for this server, which is unexpected.
		conn.Close()
		return
	}

	select {
	case pool <- conn:
		// Connection returned to the pool.
	default:
		// Pool is full, close the connection.
		conn.Close()
	}
}

// Exchange sends a DNS query to the specified server and returns the response.
// It tries UDP first, and falls back to TCP if the response is truncated.
func (c *DNSClient) Exchange(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	// Try UDP first
	resp, _, err := c.udpClient.ExchangeContext(ctx, req, server)

	// If UDP succeeded and not truncated, return result
	if err == nil && resp != nil && !resp.Truncated {
		return resp, nil
	}

	// If UDP failed with a timeout or other error, we usually let the caller handle it (try next server).
	// However, if it's truncated, we MUST retry with TCP.
	if resp != nil && resp.Truncated {
		return c.exchangeTCP(ctx, req, server)
	}

	// Return the UDP error/response if we didn't fallback to TCP
	return resp, err
}

// exchangeTCP performs a DNS exchange over TCP using the connection pool.
func (c *DNSClient) exchangeTCP(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	conn, err := c.getTcpConn(server)
	if err != nil {
		return nil, err
	}

	// Use a channel to signal completion.
	done := make(chan error, 1)
	var resp *dns.Msg
	go func() {
		var err error
		defer func() {
			done <- err
		}()

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetWriteDeadline(deadline)
		} else {
			conn.SetWriteDeadline(time.Now().Add(c.timeout))
		}
		err = conn.WriteMsg(req)
		if err != nil {
			return
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetReadDeadline(deadline)
		} else {
			conn.SetReadDeadline(time.Now().Add(c.timeout))
		}

		resp, err = conn.ReadMsg()
	}()

	select {
	case <-ctx.Done():
		conn.Close() // Context cancelled, connection state is uncertain, so close it.
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			conn.Close() // Query failed, connection might be broken, so close it.
			return nil, err
		}
		// On success, return the healthy connection to the pool.
		c.putTcpConn(conn)
		return resp, nil
	}
}

// Close closes all connections in all pools.
func (c *DNSClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	for _, pool := range c.tcpPools {
		close(pool)
		for conn := range pool {
			if conn != nil {
				conn.Close()
			}
		}
	}
	c.tcpPools = make(map[string]chan *dns.Conn) // Clear the map
}
