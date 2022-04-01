package fwd

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/3rd/netx"
	"github.com/advancevillage/fwd/pkg/fwd"
	"github.com/advancevillage/fwd/proto"
)

var (
	HttpRequestBodyCode = uint32(1000)
	JsonFromatCode      = uint32(1100)
	NotSupportCode      = uint32(1101)
	UpdateCode          = uint32(1200)
	QueryCode           = uint32(1201)

	HttpRequestBodyErr = "read request body error"
	JsonFormatErr      = "json format error"
	NotSupportMsg      = "not support action error"
	UpdateMsg          = "update forward error"
	QueryMsg           = "query forward error"

	SrvOk  = uint32(http.StatusOK)
	SrvErr = uint32(http.StatusInternalServerError)
)

type updateRequest struct {
	proto.ActionRequest
	SrcMac string `json:"srcMac"`
	DstMac string `json:"dstMac"`
	Iface  uint32 `json:"iface"`
	Ip     string `json:"ip"`
}

type updateResponse struct {
	proto.ActionResponse
}

type queryRequest struct {
	proto.ActionRequest
}

type queryResponse struct {
	proto.ActionResponse
	Tables []*fwd.FwdElem
}

func (s *Srv) httpHandler(ctx context.Context, wr netx.IHTTPWriteReader) {
	//1. 解析参数
	var reply = &proto.ActionResponse{
		Code: SrvErr,
	}
	var b, err = wr.Read()
	if err != nil {
		reply.Errors = append(reply.Errors, &proto.Error{Code: HttpRequestBodyCode, Msg: HttpRequestBodyErr})
		wr.Write(http.StatusOK, reply)
		return
	}
	var req = &proto.ActionRequest{}
	err = json.Unmarshal(b, req)
	if err != nil {
		reply.Errors = append(reply.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
		wr.Write(http.StatusOK, reply)
		return
	}
	//2. 提取TraceId
	var sctx = context.WithValue(ctx, logx.TraceId, req.GetTraceId())
	reply.TraceId = req.GetTraceId()

	//3. 请求处理
	switch req.GetAction() {
	case "UpdateForward":
		var (
			request  = &updateRequest{}
			response = &updateResponse{}
		)
		response.TraceId = reply.GetTraceId()

		err = json.Unmarshal(b, request)
		if err != nil {
			response.Code = SrvErr
			response.Errors = append(response.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
			wr.Write(http.StatusOK, response)
		} else {
			response.Code = SrvOk
			s.updateForward(sctx, response, request)
		}

		wr.Write(http.StatusOK, response)
	case "QueryForward":
		var (
			request  = &queryRequest{}
			response = &queryResponse{}
		)
		response.TraceId = reply.GetTraceId()

		err = json.Unmarshal(b, request)
		if err != nil {
			response.Code = SrvErr
			response.Errors = append(response.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
			wr.Write(http.StatusOK, response)
		} else {
			response.Code = SrvOk
			s.queryForward(sctx, response, request)
		}

		wr.Write(http.StatusOK, response)
	default:
		reply.Errors = append(reply.Errors, &proto.Error{Code: NotSupportCode, Msg: NotSupportMsg})
		wr.Write(http.StatusOK, reply)
	}
}

func (s *Srv) updateForward(ctx context.Context, response *updateResponse, request *updateRequest) {
	var err = s.fwdCli.UptFwd(ctx, request.Ip, request.Iface, request.SrcMac, request.DstMac)
	if err != nil {
		s.logger.Errorw(ctx, "update forward fail", "err", err)
		response.Errors = append(response.Errors, &proto.Error{Code: UpdateCode, Msg: UpdateMsg})
		response.Code = SrvErr
	}
}

func (s *Srv) queryForward(ctx context.Context, response *queryResponse, request *queryRequest) {
	var tables, err = s.fwdCli.QryFwd(ctx)
	if err != nil {
		s.logger.Errorw(ctx, "query forward fail", "err", err)
		response.Errors = append(response.Errors, &proto.Error{Code: QueryCode, Msg: QueryMsg})
		response.Code = SrvErr
	}
	response.Tables = tables
}
