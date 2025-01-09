// Copyright 2016 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fatedier/golib/crypto"
	quic "github.com/quic-go/quic-go"

	"github.com/fatedier/frp/pkg/util/xlog"
)

type ContextGetter interface {
	Context() context.Context
}

type ContextSetter interface {
	WithContext(ctx context.Context)
}

func NewLogFromConn(conn net.Conn) *xlog.Logger {
	if c, ok := conn.(ContextGetter); ok {
		return xlog.FromContextSafe(c.Context())
	}
	return xlog.New()
}

func NewContextFromConn(conn net.Conn) context.Context {
	if c, ok := conn.(ContextGetter); ok {
		return c.Context()
	}
	return context.Background()
}

// ContextConn is the connection with context
type ContextConn struct {
	net.Conn

	ctx context.Context
}

func NewContextConn(ctx context.Context, c net.Conn) *ContextConn {
	return &ContextConn{
		Conn: c,
		ctx:  ctx,
	}
}

func (c *ContextConn) WithContext(ctx context.Context) {
	c.ctx = ctx
}

func (c *ContextConn) Context() context.Context {
	return c.ctx
}

type WrapReadWriteCloserConn struct {
	io.ReadWriteCloser

	underConn net.Conn

	remoteAddr net.Addr
}

func WrapReadWriteCloserToConn(rwc io.ReadWriteCloser, underConn net.Conn) *WrapReadWriteCloserConn {
	return &WrapReadWriteCloserConn{
		ReadWriteCloser: rwc,
		underConn:       underConn,
	}
}

func (conn *WrapReadWriteCloserConn) LocalAddr() net.Addr {
	if conn.underConn != nil {
		return conn.underConn.LocalAddr()
	}
	return (*net.TCPAddr)(nil)
}

func (conn *WrapReadWriteCloserConn) SetRemoteAddr(addr net.Addr) {
	conn.remoteAddr = addr
}

func (conn *WrapReadWriteCloserConn) RemoteAddr() net.Addr {
	if conn.remoteAddr != nil {
		return conn.remoteAddr
	}
	if conn.underConn != nil {
		return conn.underConn.RemoteAddr()
	}
	return (*net.TCPAddr)(nil)
}

func (conn *WrapReadWriteCloserConn) SetDeadline(t time.Time) error {
	if conn.underConn != nil {
		return conn.underConn.SetDeadline(t)
	}
	return &net.OpError{Op: "set", Net: "wrap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (conn *WrapReadWriteCloserConn) SetReadDeadline(t time.Time) error {
	if conn.underConn != nil {
		return conn.underConn.SetReadDeadline(t)
	}
	return &net.OpError{Op: "set", Net: "wrap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (conn *WrapReadWriteCloserConn) SetWriteDeadline(t time.Time) error {
	if conn.underConn != nil {
		return conn.underConn.SetWriteDeadline(t)
	}
	return &net.OpError{Op: "set", Net: "wrap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

type CloseNotifyConn struct {
	net.Conn

	closeFlag sync.Once

	closeFn func()
}

// closeFn will be only called once
func WrapCloseNotifyConn(c net.Conn, closeFn func()) net.Conn {
	return &CloseNotifyConn{
		Conn:    c,
		closeFn: closeFn,
	}
}

func (cc *CloseNotifyConn) Close() (err error) {
	cc.closeFlag.Do(func() {
		err = cc.Close()
		if cc.closeFn != nil {
			cc.closeFn()
		}
	})
	return
}

type StatsConn struct {
	net.Conn

	closed  sync.Once
	onRead  func(n int)
	onWrite func(n int)
	onClose func()
}

func WrapStatsConn(conn net.Conn, onRead func(n int), onWrite func(n int), onClose func()) *StatsConn {
	return &StatsConn{
		Conn:    conn,
		onRead:  onRead,
		onWrite: onWrite,
		onClose: onClose,
	}
}

func (statsConn *StatsConn) Read(p []byte) (n int, err error) {
	n, err = statsConn.Conn.Read(p)
	statsConn.onRead(n)
	return
}

func (statsConn *StatsConn) Write(p []byte) (n int, err error) {
	n, err = statsConn.Conn.Write(p)
	statsConn.onWrite(n)
	return
}

func (statsConn *StatsConn) Close() (err error) {
	statsConn.closed.Do(func() {
		err = statsConn.Conn.Close()
		statsConn.onClose()
	})
	return
}

type wrapQuicStream struct {
	quic.Stream
	c quic.Connection
}

func QuicStreamToNetConn(s quic.Stream, c quic.Connection) net.Conn {
	return &wrapQuicStream{
		Stream: s,
		c:      c,
	}
}

func (conn *wrapQuicStream) LocalAddr() net.Addr {
	if conn.c != nil {
		return conn.c.LocalAddr()
	}
	return (*net.TCPAddr)(nil)
}

func (conn *wrapQuicStream) RemoteAddr() net.Addr {
	if conn.c != nil {
		return conn.c.RemoteAddr()
	}
	return (*net.TCPAddr)(nil)
}

func (conn *wrapQuicStream) Close() error {
	conn.Stream.CancelRead(0)
	return conn.Stream.Close()
}

func NewCryptoReadWriter(rw io.ReadWriter, key []byte) (io.ReadWriter, error) {
	encReader := crypto.NewReader(rw, key)
	encWriter, err := crypto.NewWriter(rw, key)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Writer
	}{
		Reader: encReader,
		Writer: encWriter,
	}, nil
}
