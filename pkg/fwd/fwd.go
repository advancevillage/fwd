package fwd

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/fwd/pkg/bpf"
)

var (
	keySize   = int(0x04)
	valueSize = int(0x10)
	maxSize   = int(10000)
	name      = "hfwd"
)

type fwdCli struct {
	tableCli  bpf.ITable
	logger    logx.ILogger
	keySize   int
	valueSize int
}

type FwdElem struct {
	Ip     string
	Iface  uint32
	SrcMac string
	DstMac string
}

type IFwd interface {
	QryFwd(ctx context.Context) ([]*FwdElem, error)
	DelFwd(ctx context.Context, dstIp string) error
	UptFwd(ctx context.Context, dstIp string, ifaceIndex uint32, srcmac string, dstmac string) error
}

func NewFwdClient(logger logx.ILogger) (IFwd, error) {
	var cli, err = bpf.NewTableClient(logger, name, "lru_hash", keySize, valueSize, maxSize)
	if err != nil {
		return nil, err
	}
	return &fwdCli{
		tableCli:  cli,
		keySize:   keySize,
		valueSize: valueSize,
		logger:    logger,
	}, nil
}

//设置转发表
//ifaceIndx   网络设备标示，表示从哪张设备转发
//srcmac	  源MAC
//dstmac	  目的MAC
func (d *fwdCli) UptFwd(ctx context.Context, dstIp string, ifaceIndex uint32, srcmac string, dstmac string) error {
	//1. 参数检查
	ip, err := d.checkip(dstIp)
	if err != nil {
		return err
	}
	src, err := d.checkmac(srcmac)
	if err != nil {
		return err
	}
	dst, err := d.checkmac(dstmac)
	if err != nil {
		return err
	}

	k, v := d.kv(ip, ifaceIndex, src, dst)

	err = d.update(ctx, k, v)
	if err != nil {
		return err
	}

	return nil
}

func (d *fwdCli) DelFwd(ctx context.Context, dstIp string) error {
	ip, err := d.checkip(dstIp)
	if err != nil {
		return err
	}
	return d.delete(ctx, ip)
}

func (d *fwdCli) QryFwd(ctx context.Context) ([]*FwdElem, error) {
	return d.query(ctx)
}

func (i *fwdCli) update(ctx context.Context, key []byte, value []byte) error {
	var err error
	if !i.tableCli.ExistTable(ctx) {
		err = i.tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	if len(key) != i.keySize {
		return errors.New("key size is invalid")
	}
	if len(value) != i.valueSize {
		return errors.New("value size is invalid")
	}
	err = i.tableCli.UpdateTable(ctx, key, value)
	if err != nil {
		return err
	}
	return nil
}

func (i *fwdCli) delete(ctx context.Context, key []byte) error {
	var err error
	if !i.tableCli.ExistTable(ctx) {
		err = i.tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	if len(key) != i.keySize {
		return errors.New("key size is invalid")
	}
	err = i.tableCli.DeleteTable(ctx, key)
	if err != nil {
		return err
	}
	return nil
}

func (i *fwdCli) query(ctx context.Context) ([]*FwdElem, error) {
	var r = make([]*FwdElem, 0, 2)
	if i.tableCli == nil {
		return r, nil
	}
	if !i.tableCli.ExistTable(ctx) {
		return r, nil
	}
	var kv, err = i.tableCli.QueryTable(ctx)
	if err != nil {
		return r, err
	}
	for i := range kv {
		var (
			kk = kv[i].Key
			vv = kv[i].Value
			rr = new(FwdElem)
		)
		rr.Ip = net.IPv4(kk[3], kk[2], kk[1], kk[0]).String()
		rr.Iface |= uint32(vv[0])
		rr.Iface |= uint32(vv[1]) << 8
		rr.Iface |= uint32(vv[2]) << 16
		rr.Iface |= uint32(vv[3]) << 24
		rr.SrcMac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", vv[4], vv[5], vv[6], vv[7], vv[8], vv[9])
		rr.DstMac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", vv[0xa], vv[0xb], vv[0xc], vv[0xd], vv[0xe], vv[0xf])

		r = append(r, rr)
	}
	return r, nil
}

func (d *fwdCli) kv(ip []byte, ifaceIndex uint32, src []byte, dst []byte) ([]byte, []byte) {
	var k = make([]byte, d.keySize)
	var v = make([]byte, d.valueSize)

	copy(k, ip)

	v[0] = byte(ifaceIndex)
	v[1] = byte(ifaceIndex >> 8)
	v[2] = byte(ifaceIndex >> 16)
	v[3] = byte(ifaceIndex >> 24)
	copy(v[4:10], src)
	copy(v[10:16], dst)

	return k, v
}

func (d *fwdCli) checkip(ip string) ([]byte, error) {
	netip := net.ParseIP(ip)
	if netip == nil {
		return nil, errors.New("invalid ip format")
	}
	addr := netip.To4()
	if addr == nil {
		return nil, errors.New("invalid ip format")
	}
	b := make([]byte, 4)

	b[0] = addr[3]
	b[1] = addr[2]
	b[2] = addr[1]
	b[3] = addr[0]

	return b, nil
}

//eg: 08:00:27:f3:81:0e
func (d *fwdCli) checkmac(mac string) ([]byte, error) {
	var hw, err = net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	mac = hw.String()
	b := make([]byte, 6)
	j := 0

	for i := 0; i < len(mac) && j < 6; i++ {
		if mac[i] == ':' {
			j++
			continue
		}
		v := byte(0)
		switch mac[i] {
		case '0':
			v = 0x0
		case '1':
			v = 0x1
		case '2':
			v = 0x2
		case '3':
			v = 0x3
		case '4':
			v = 0x4
		case '5':
			v = 0x5
		case '6':
			v = 0x6
		case '7':
			v = 0x7
		case '8':
			v = 0x8
		case '9':
			v = 0x9
		case 'a', 'A':
			v = 0xa
		case 'b', 'B':
			v = 0xb
		case 'c', 'C':
			v = 0xc
		case 'd', 'D':
			v = 0xd
		case 'e', 'E':
			v = 0xe
		case 'f', 'F':
			v = 0xf
		default:
			return nil, errors.New("invalid mac address")
		}
		b[j] = b[j]<<4 | v
	}

	return b, nil
}
