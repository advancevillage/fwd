package bpf

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/advancevillage/3rd/logx"
)

type ITable interface {
	GCTable(ctx context.Context) error
	ExistTable(ctx context.Context) bool
	CreateTable(ctx context.Context) error
	QueryTable(ctx context.Context) ([]*KV, error)
	DeleteTable(ctx context.Context, key []byte) error
	UpdateTable(ctx context.Context, key []byte, value []byte) error
}

type KV struct {
	Key   []byte `json:"key"`
	Value []byte `json:"Value"`
}

const (
	bpf_f_prealloc    = 0
	bpf_f_no_prealloc = 1
)

type table struct {
	tYpe       string
	file       string
	keySize    int
	valueSize  int
	maxEntries int
	flags      int
	logger     logx.ILogger
}

func NewTableClient(logger logx.ILogger, file string, tYpe string, keySize int, valueSize int, maxEntries int) (ITable, error) {
	//1. 预设类型对应的Flags
	var t = &table{
		logger: logger,
	}
	tYpe = strings.ToLower(tYpe)
	switch tYpe {
	case "hash", "lru_hash":
		t.flags = bpf_f_no_prealloc
		if keySize < 1 || valueSize < 1 {
			return nil, fmt.Errorf("keySize or valueSize param are invalid")
		}
	case "array":
		if keySize != 4 {
			return nil, fmt.Errorf("keySize param is invalid")
		}
		t.flags = bpf_f_prealloc
	case "lpm_trie":
		t.flags = bpf_f_no_prealloc
		if keySize < 5 || keySize > 260 {
			return nil, fmt.Errorf("keySize param is invalid")
		}
		if valueSize < 1 || valueSize > (65535-260) {
			return nil, fmt.Errorf("valueSize param is invalid")
		}
	case "hash_of_maps":
		t.flags = bpf_f_no_prealloc
		if valueSize != 4 {
			return nil, fmt.Errorf("valueSize param is invalid")
		}
	default:
		return nil, fmt.Errorf("don't support %s map type", tYpe)
	}
	t.file = file
	t.tYpe = tYpe
	t.keySize = keySize
	t.valueSize = valueSize
	t.maxEntries = maxEntries
	return t, nil
}

func (t *table) CreateTable(ctx context.Context) error {
	var ebpf = newBpfTool(
		withLog(t.logger),
		withExec(),
		withJSON(),
		withMap(),
		withCreateMapCmd(t.file, t.file, t.tYpe, t.keySize, t.valueSize, t.maxEntries, t.flags),
	)
	var r string
	var errs = new(bpfErr)
	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) UpdateTable(ctx context.Context, key []byte, value []byte) error {
	if len(key) != t.keySize {
		return fmt.Errorf("key len is not %d", t.keySize)
	}
	if len(value) != t.valueSize {
		return fmt.Errorf("value len is not %d", t.valueSize)
	}
	var ebpf = newBpfTool(
		withLog(t.logger),
		withExec(),
		withJSON(),
		withMap(),
		withUpdateMapCmd(t.file, key, value, "any"),
	)
	var r string
	var errs = new(bpfErr)
	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) QueryTable(ctx context.Context) ([]*KV, error) {
	var ebpf = newBpfTool(
		withLog(t.logger),
		withExec(),
		withJSON(),
		withMap(),
		withDumpMapCmd(t.file),
	)
	type kv struct {
		Key   []string `json:"key"`
		Value []string `json:"value"`
	}
	type kvList []kv

	var r = new(kvList)
	var errs = new(bpfErr)
	//eg: 正常
	//
	// [{"key":["0x12","0x34","0x56","0x78"],"value":["0x87","0x65","0x43","0x21"]}]
	//
	//eg:  不存在
	//
	// {"error":"bpf obj get (/sys/fs/bpf/nikjklkdjf): No such file or directory"}
	//
	//eg:

	var err = ebpf.run(ctx, r, errs)
	if err != nil {
		return nil, err
	}

	if len(errs.Err) > 0 {
		return nil, errors.New(errs.Err)
	}
	var rr = make([]*KV, 0, len(*r))
	for i := range *r {
		var v = &KV{
			Key:   make([]byte, t.keySize),
			Value: make([]byte, t.valueSize),
		}
		for ii := range (*r)[i].Key {
			v.Key[ii] = t.hex((*r)[i].Key[ii])
		}
		for ii := range (*r)[i].Value {
			v.Value[ii] = t.hex((*r)[i].Value[ii])
		}
		rr = append(rr, v)
	}
	return rr, nil
}

func (t *table) ExistTable(ctx context.Context) bool {
	var ebpf = newBpfTool(
		withLog(t.logger),
		withExec(),
		withJSON(),
		withMap(),
		withShowMapCmd(),
	)
	var r = new(bpfMaps)
	var errs = new(bpfErr)
	var err = ebpf.run(ctx, r, errs)
	if err != nil {
		return true
	}
	var exist = false
	for i := range *r {
		if (*r)[i].Name == t.file {
			exist = true
			break
		} else {
			continue
		}
	}
	return exist
}

func (t *table) DeleteTable(ctx context.Context, key []byte) error {
	if len(key) != t.keySize {
		return fmt.Errorf("key len is not %d", t.keySize)
	}
	var ebpf = newBpfTool(
		withLog(t.logger),
		withExec(),
		withJSON(),
		withMap(),
		withDeleteMapCmd(t.file, key),
	)
	var r = make(map[string]interface{})
	var errs = new(bpfErr)

	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) GCTable(ctx context.Context) error {
	var ebpf = newBpfTool(
		withLog(t.logger),
	)
	return ebpf.unlink(ctx, t.file)
}

func (t *table) hex(s string) byte {
	var v = byte(0)
	var vv = byte(0)
	//0x12 0xa 12
	for i := len(s) - 1; i >= 0 && s[i] != 'x'; i-- {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			vv = s[i] - '0'
		case 'a', 'A':
			vv = 10
		case 'b', 'B':
			vv = 11
		case 'c', 'C':
			vv = 12
		case 'd', 'D':
			vv = 13
		case 'e', 'E':
			vv = 14
		case 'f', 'F':
			vv = 15
		}
		v += vv * t.pow(0x10, len(s)-1-i)
	}
	return v
}

func (t *table) pow(x, n int) byte {
	switch {
	case n <= 0:
		return 0x01
	default:
		for i := 1; i < n; i++ {
			x *= x
		}
		return byte(x)
	}
}
