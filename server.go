package fwd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/3rd/netx"
	"github.com/advancevillage/fwd/pkg/fwd"
)

type SrvCfg struct {
	LogCfg struct {
		Level string `json:"level"`
	} `json:"logCfg"`

	HttpCfg struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"httpCfg"`
}

type Srv struct {
	cfg     *SrvCfg
	fwdCli  fwd.IFwd
	httpSrv netx.IHTTPServer
	logger  logx.ILogger
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewSrv(cfg *SrvCfg) (*Srv, error) {
	//1. logger
	var (
		s           = &Srv{}
		ctx, cancel = context.WithCancel(context.Background())
	)

	logger, err := logx.NewLogger(cfg.LogCfg.Level)
	if err != nil {
		panic(err)
	}
	//2. httpSrv
	r := netx.NewHTTPRouter()
	r.Add(http.MethodPost, "/", s.httpHandler)

	srv, err := netx.NewHTTPSrv(netx.WithHTTPSrvLogger(logger), netx.WithHTTPSrvAddr(cfg.HttpCfg.Host, cfg.HttpCfg.Port), netx.WithHTTPSrvRts(r), netx.WithHTTPSrvCtx(ctx, cancel))
	if err != nil {
		panic(err)
	}
	//3. fw
	fwdCli, err := fwd.NewFwdClient(logger)
	if err != nil {
		panic(err)
	}

	s.logger = logger
	s.httpSrv = srv
	s.ctx = ctx
	s.cancel = cancel
	s.cfg = cfg
	s.fwdCli = fwdCli

	return s, nil
}

func (s *Srv) Start() {
	s.logger.Infow(s.ctx, "start server", "listen http", fmt.Sprintf("%s:%d", s.cfg.HttpCfg.Host, s.cfg.HttpCfg.Port))
	go s.httpSrv.Start()
	select {
	case <-s.httpSrv.Exit():
	case <-s.ctx.Done():
	}
	s.logger.Infow(s.ctx, "exit server", "listen http", fmt.Sprintf("%s:%d", s.cfg.HttpCfg.Host, s.cfg.HttpCfg.Port))
}
