//go:build linux

package conntrack

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

const netlinkNetfilter = 12

// Client is one netlink socket, safe for concurrent use. Lookups are
// serialised; each is a single request and reply.
type Client struct {
	mu  sync.Mutex
	fd  int
	seq uint32
}

// Open connects to ctnetlink. It fails where the process may not read the
// conntrack table (no CAP_NET_ADMIN, or nf_conntrack_netlink missing).
func Open() (*Client, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// The kernel answers from memory in microseconds; a slow reply means
	// something is wrong, and the caller backs off.
	tv := syscall.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink timeout: %w", err)
	}
	return &Client{fd: fd}, nil
}

// Close releases the socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := syscall.Close(c.fd)
	c.fd = -1
	return err
}

// OriginalDst returns where the sender addressed the flow that reached local
// from remote. proto is the IP protocol number (17 for UDP).
func (c *Client) OriginalDst(proto uint8, remote, local netip.AddrPort) (netip.AddrPort, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return netip.AddrPort{}, errors.New("conntrack client closed")
	}
	c.seq++
	req, err := getRequest(c.seq, proto, remote, local)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if err := syscall.Sendto(c.fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 8192)
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("netlink receive: %w", err)
		}
		dst, done, err := parseReply(buf[:n], c.seq)
		if done {
			return dst, err
		}
	}
}
