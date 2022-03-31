package bpf

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/advancevillage/3rd/logx"
)

var testTable = map[string]struct {
	file       string
	tYpe       string
	keySize    int
	valueSize  int
	maxEntries int
}{
	//普通普通类型
	"case1": {
		tYpe:       "hash",
		keySize:    4,
		valueSize:  4,
		maxEntries: 64,
	},
	//结构体
}

func Test_table(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	for n, p := range testTable {
		f := func(t *testing.T) {
			p.file = randStr(8)
			var ta, err = NewTableClient(logger, p.file, p.tYpe, p.keySize, p.valueSize, p.maxEntries)
			if err != nil {
				t.Fatal(err)
				return
			}
			//1. 创建表
			var ctx, cancel = context.WithTimeout(context.Background(), time.Second*20)
			defer cancel()

			err = ta.CreateTable(ctx)
			if err != nil {
				t.Fatal("create table fail", err)
				return
			}
			//2. 准备数据
			var data = make([]*KV, 0, p.maxEntries)
			for i := 0; i < p.maxEntries; i++ {
				data = append(data, &KV{
					Key:   []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
					Value: []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
				})
			}
			//3. 更新数据
			for _, v := range data {
				err = ta.UpdateTable(ctx, v.Key, v.Value)
				if err != nil {
					t.Fatal(err)
					return
				}
			}
			//4. 查询
			act, err := ta.QueryTable(ctx)
			if err != nil {
				t.Fatal(err)
				return
			}
			//5. 输出
			for i := 0; i < p.maxEntries; i++ {
				var v = data[i]
				var j = 0
				for ; j < p.maxEntries; j++ {
					var vv = act[j]
					if bytes.Equal(v.Key, vv.Key) && bytes.Equal(v.Value, vv.Value) {
						break
					} else {
						continue
					}
				}
				if j >= p.maxEntries {
					t.Fatal(data[i], "don't found")
					return
				}
			}
			for j := 0; j < p.maxEntries; j++ {
				var v = act[j]
				var i = 0
				for ; i < p.maxEntries; i++ {
					var vv = data[i]
					if bytes.Equal(v.Key, vv.Key) && bytes.Equal(v.Value, vv.Value) {
						break
					} else {
						continue
					}
				}
				if i >= p.maxEntries {
					t.Fatal(act[j], "don't found")
					return
				}
			}
			//4. 删除一半
			for i := 0; i < p.maxEntries/2; i++ {
				err = ta.DeleteTable(ctx, data[i].Key)
				if err != nil {
					t.Fatal("delete fail", err)
					return
				}
			}
			data = data[p.maxEntries/2:]
			p.maxEntries = p.maxEntries - p.maxEntries/2
			//4. 查询
			act, err = ta.QueryTable(ctx)
			if err != nil {
				t.Fatal(err)
				return
			}
			for i := 0; i < p.maxEntries; i++ {
				var v = data[i]
				var j = 0
				for ; j < p.maxEntries; j++ {
					var vv = act[j]
					if bytes.Equal(v.Key, vv.Key) && bytes.Equal(v.Value, vv.Value) {
						break
					} else {
						continue
					}
				}
				if j >= p.maxEntries {
					t.Fatal(data[i], "don't found")
					return
				}
			}
			for j := 0; j < p.maxEntries; j++ {
				var v = act[j]
				var i = 0
				for ; i < p.maxEntries; i++ {
					var vv = data[i]
					if bytes.Equal(v.Key, vv.Key) && bytes.Equal(v.Value, vv.Value) {
						break
					} else {
						continue
					}
				}
				if i >= p.maxEntries {
					t.Fatal(act[j], "don't found")
					return
				}
			}
			//6. 表查询判断
			var exist = ta.ExistTable(ctx)
			if !exist {
				t.Fatal(exist, "table should be exist")
				return
			}
			//7. 回收表
			err = ta.GCTable(ctx)
			if err != nil {
				t.Fatal("gc table fail", err)
				return
			}
			exist = ta.ExistTable(ctx)
			if exist {
				t.Fatal(exist, "table should not be exist")
				return
			}
		}
		t.Run(n, f)
	}
}

var testinnerTable = map[string]struct {
	inner           string
	outer           string
	innerType       string
	outerType       string
	innerKeySize    int
	outterKeySize   int
	innerValueSzie  int
	outerValueSzie  int
	innerMaxEntries int
	outerMaxEntries int
	debug           bool
}{
	"case-lpm-hashinmap": {
		inner:           randStr(4),
		outer:           randStr(4),
		innerType:       "lpm_trie",
		outerType:       "hash_of_maps",
		innerKeySize:    8,
		innerValueSzie:  16,
		outterKeySize:   48,
		outerValueSzie:  4,
		innerMaxEntries: 16,
		outerMaxEntries: 16,
		debug:           false,
	},
}

func Test_hash_in_map(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	for n, p := range testinnerTable {
		f := func(t *testing.T) {
			var inner, err = NewTableClient(logger, p.inner, p.innerType, p.innerKeySize, p.innerValueSzie, p.innerMaxEntries)
			if err != nil {
				t.Fatal(err)
				return
			}
			//1. 创建内表
			var ctx, cancel = context.WithTimeout(context.Background(), time.Second*20)
			defer cancel()

			err = inner.CreateTable(ctx)
			if err != nil && !p.debug {
				t.Fatal("create inner table fail", err)
				return
			}

			//2. 创建外表
			outer, err := NewTableClient(logger, p.outer, p.outerType, p.outterKeySize, p.outerValueSzie, p.outerMaxEntries)
			if err != nil {
				t.Fatal(err)
				return
			}
			err = outer.CreateMapInMapTable(ctx, p.inner)
			if err != nil && !p.debug {
				t.Fatal("create outer table fail", err)
				return
			}
			//3. 更新内表
			var key = "security.protocol"
			var kk = make([]byte, p.outterKeySize)
			copy(kk, []byte(key))
			err = outer.UpdateMapInMapTable(ctx, kk, p.inner)
			if err != nil && !p.debug {
				t.Fatal("update outer table fail", err)
				return
			}
			//4. 查询值
			kv, err := outer.QueryTable(ctx)
			if err != nil && !p.debug {
				t.Fatal("query outer table fail", err)
				return
			}
			if len(kv) != 1 {
				t.Fatal("<> 1")
				return
			}
			kk2 := kv[0].Key
			if !bytes.Equal(kk, kk2) {
				t.Fatal(fmt.Sprintf("%v != %v", kk, kk2))
				return
			}
			//5. 回收表
			err = inner.GCTable(ctx)
			if err != nil {
				t.Fatal(err)
				return
			}
			err = outer.GCTable(ctx)
			if err != nil {
				t.Fatal(err)
				return
			}
		}
		t.Run(n, f)
	}
}

var testHex = map[string]struct {
	h byte
	s string
}{
	"case1": {
		h: 0x21,
		s: "0x21",
	},
	"case2": {
		h: 0x01,
		s: "0x01",
	},
	"case3": {
		h: 0xf,
		s: "0xf",
	},
	"case4": {
		h: 0x0f,
		s: "0x0f",
	},
	"case5": {
		h: 0x00,
		s: "0x00",
	},
}

func Test_hex(t *testing.T) {
	var ta = &table{}
	for n, p := range testHex {
		f := func(t *testing.T) {
			var hh = ta.hex(p.s)
			if hh != p.h {
				t.Fatal(hh, "<>", p.h)
			}
		}
		t.Run(n, f)
	}
}

func randStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}
