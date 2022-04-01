package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/advancevillage/fwd"
)

func main() {
	//1. load cfg
	cfg, err := loadCfg()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = checkCfg(cfg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	srv, err := fwd.NewSrv(cfg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	srv.Start()
}

func loadCfg() (*fwd.SrvCfg, error) {
	var cfgPath string
	flag.StringVar(&cfgPath, "c", "conf/fwd.json", "path to config")
	if !flag.Parsed() {
		flag.Parse()
	}
	if len(cfgPath) <= 0 {
		cfgPath = "conf/fwd.json"
	}
	buf, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	cfg := &fwd.SrvCfg{}
	err = json.Unmarshal(buf, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func checkCfg(cfg *fwd.SrvCfg) error {
	if cfg == nil {
		return errors.New("cfg is nil")
	}
	if nil == net.ParseIP(cfg.HttpCfg.Host) {
		return errors.New("httpCfg.Host is invalid")
	}
	if cfg.HttpCfg.Port <= 0 || cfg.HttpCfg.Port >= 65535 {
		return errors.New("httpCfg.Port is invalid")
	}
	return nil
}
