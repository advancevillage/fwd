package fwd

import (
	"context"
	"errors"
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

type IFwd interface {
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
