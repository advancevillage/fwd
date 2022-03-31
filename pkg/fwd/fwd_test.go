package fwd

import (
	"net"
	"testing"

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
