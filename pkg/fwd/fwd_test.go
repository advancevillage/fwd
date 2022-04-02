package fwd

import (
	"context"
	"net"
	"testing"

	"github.com/advancevillage/3rd/logx"
	"github.com/stretchr/testify/assert"
)

var macTest = map[string]struct {
	mac string
	exp []byte
	err error
}{
	"case1": {
		mac: "08:00:27:f3:81:0e",
		exp: []byte{0x08, 0x00, 0x27, 0xf3, 0x81, 0x0e},
		err: nil,
	},
	"case2": {
		mac: ":00:27:f3:81:0e",
		exp: []byte{0x00, 0x00, 0x27, 0xf3, 0x81, 0x0e},
		err: &net.AddrError{Err: "invalid MAC address", Addr: ":00:27:f3:81:0e"},
	},
	"case3": {
		mac: "00:27:f3:81:0e",
		exp: []byte{0x00, 0x00, 0x27, 0xf3, 0x81, 0x0e},
		err: &net.AddrError{Err: "invalid MAC address", Addr: "00:27:f3:81:0e"},
	},
}

func Test_mac_check(t *testing.T) {
	var c = &fwdCli{}

	for n, p := range macTest {
		f := func(t *testing.T) {
			var act, err = c.checkmac(p.mac)
			if err != nil {
				assert.Equal(t, p.err, err)
			} else {
				assert.Equal(t, p.exp, act)
			}
		}
		t.Run(n, f)
	}
}

var ipTest = map[string]struct {
	dstIp string
	exp   []byte
	err   error
}{
	"case1": {
		dstIp: "127.0.0.1",
		exp:   []byte{0x7f, 0x00, 0x00, 0x01},
	},
}

func Test_ip_check(t *testing.T) {
	var c = &fwdCli{}

	for n, p := range ipTest {
		f := func(t *testing.T) {
			var act, err = c.checkip(p.dstIp)
			if err != nil {
				assert.Equal(t, p.err, err)
			} else {
				assert.Equal(t, p.exp, act)
			}
		}
		t.Run(n, f)
	}
}

var kvTest = map[string]struct {
	ip    []byte
	src   []byte
	dst   []byte
	iface uint32
	k     []byte
	v     []byte
}{
	"case1": {
		ip:    []byte{0x01, 0x00, 0x00, 0x7f},
		src:   []byte{0x08, 0x00, 0x27, 0xf3, 0x81, 0x0e},
		dst:   []byte{0xf8, 0xf0, 0x27, 0xf3, 0x81, 0x0e},
		iface: 4,
		k:     []byte{0x01, 0x00, 0x00, 0x7f},
		v:     []byte{0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x27, 0xf3, 0x81, 0x0e, 0xf8, 0xf0, 0x27, 0xf3, 0x81, 0x0e},
	},
}

func Test_kv_check(t *testing.T) {
	var c = &fwdCli{
		keySize:   keySize,
		valueSize: valueSize,
	}

	for n, p := range kvTest {
		f := func(t *testing.T) {
			var k, v = c.kv(p.ip, p.iface, p.src, p.dst)
			assert.Equal(t, p.k, k)
			assert.Equal(t, p.v, v)
		}
		t.Run(n, f)
	}
}

var uptTest = map[string]struct {
	dstIp string
	src   string
	dst   string
	iface uint32
	exp   []*FwdElem
}{
	"case1": {
		dstIp: "192.168.1.103",
		src:   "08:00:27:f3:81:0e",
		dst:   "f8:ff:27:f3:81:0e",
		iface: 4,
		exp:   []*FwdElem{},
	},
}

func Test_fwd_update(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	c, err := NewFwdClient(logger)
	if err != nil {
		t.Fatal(err)
		return
	}

	for n, p := range uptTest {
		f := func(t *testing.T) {
			var err = c.UptFwd(context.TODO(), p.dstIp, p.iface, p.src, p.dst)
			if err != nil {
				t.Fatal(err)
				return
			}
			r, err := c.QryFwd(context.TODO())
			if err != nil {
				t.Fatal(err)
				return
			}
			assert.Equal(t, p.exp, r)
		}
		t.Run(n, f)
	}

}
