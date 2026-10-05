//go:build !linux

package conntrack

import (
	"errors"
	"net/netip"
)

// Client is unavailable off Linux.
type Client struct{}

// Open always fails off Linux.
func Open() (*Client, error) { return nil, errors.New("conntrack needs Linux") }

// Close does nothing.
func (c *Client) Close() error { return nil }

// OriginalDst always fails off Linux.
func (c *Client) OriginalDst(uint8, netip.AddrPort, netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("conntrack needs Linux")
}
