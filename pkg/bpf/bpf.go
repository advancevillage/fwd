package bpf

type (
	bpfErrs []bpfErr
	bpfMaps []bpfMap
)

type bpfMap struct {
	Id           int      `json:"id"`
	Type         string   `json:"type"`
	Name         string   `json:"name"` //最大16个字符
	Flags        int      `json:"flags"`
	BytesKey     int      `json:"bytes_key"`
	BytesValue   int      `json:"bytes_value"`
	MaxEntry     int      `json:"max_entries"`
	BytesMemLock int      `json:"bytes_memlock"`
	Frozen       int      `json:"frozen"`
	BtfId        int      `json:"btf_id"`
	Pids         []bpfPid `json:"pids"`
}

type bpfPid struct {
	Pid  int    `json:"pid"`
	Comm string `json:"comm"`
}

type bpfErr struct {
	Err string `json:"error"`
}
