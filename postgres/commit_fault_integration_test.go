//go:build integration

package oauthpostgres_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

// This disposable transport seam follows the native identity registration
// integration fixture's PostgreSQL framing. It never replaces SQL/authority:
// it can withhold the COMMIT acknowledgement after an actual OAuth effect or
// schedule a bounded actual PostgreSQL row-lock wait before a named statement.
type oauthCommitFault struct {
	armed, hit  atomic.Bool
	before      bool
	beforeWrite func([]byte)
}

func (f *oauthCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &oauthFaultConn{Conn: c, fault: f}, nil
}

type oauthFaultConn struct {
	net.Conn
	fault    *oauthCommitFault
	mutation atomic.Bool
	pending  []byte // Sole pgx reader owns the bounded backend frame.
}

func (c *oauthFaultConn) Write(p []byte) (int, error) {
	if c.fault.beforeWrite != nil {
		c.fault.beforeWrite(p)
	}
	if c.fault.armed.Load() && (bytes.Contains(p, []byte(`INSERT INTO "oauth_store".effects(`)) || bytes.Contains(p, []byte(`INSERT INTO "oauth_store".device_effects(`))) {
		c.mutation.Store(true)
	}
	if c.fault.before && c.mutation.Load() && len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("commit\x00")) && c.fault.hit.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func (c *oauthFaultConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		message := make([]byte, int(size)+1)
		copy(message, header[:])
		if _, err := io.ReadFull(c.Conn, message[5:]); err != nil {
			return 0, err
		}
		if !c.fault.before && c.mutation.Load() && header[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		c.pending = message
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
