// Code generated by protoc-gen-go. DO NOT EDIT.
// source: get_transfers.proto

package model

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type GetTransfersParam struct {
	In                   bool     `protobuf:"varint,1,opt,name=in,proto3" json:"in,omitempty"`
	Out                  bool     `protobuf:"varint,2,opt,name=out,proto3" json:"out,omitempty"`
	Pending              bool     `protobuf:"varint,3,opt,name=pending,proto3" json:"pending,omitempty"`
	Failed               bool     `protobuf:"varint,4,opt,name=failed,proto3" json:"failed,omitempty"`
	Pool                 bool     `protobuf:"varint,5,opt,name=pool,proto3" json:"pool,omitempty"`
	FilterByHeight       bool     `protobuf:"varint,6,opt,name=filter_by_height,json=filterByHeight,proto3" json:"filter_by_height,omitempty"`
	MinHeight            uint64   `protobuf:"varint,7,opt,name=min_height,json=minHeight,proto3" json:"min_height,omitempty"`
	MaxHeight            uint64   `protobuf:"varint,8,opt,name=max_height,json=maxHeight,proto3" json:"max_height,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetTransfersParam) Reset()         { *m = GetTransfersParam{} }
func (m *GetTransfersParam) String() string { return proto.CompactTextString(m) }
func (*GetTransfersParam) ProtoMessage()    {}
func (*GetTransfersParam) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ae4206faa118e98, []int{0}
}

func (m *GetTransfersParam) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetTransfersParam.Unmarshal(m, b)
}
func (m *GetTransfersParam) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetTransfersParam.Marshal(b, m, deterministic)
}
func (m *GetTransfersParam) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetTransfersParam.Merge(m, src)
}
func (m *GetTransfersParam) XXX_Size() int {
	return xxx_messageInfo_GetTransfersParam.Size(m)
}
func (m *GetTransfersParam) XXX_DiscardUnknown() {
	xxx_messageInfo_GetTransfersParam.DiscardUnknown(m)
}

var xxx_messageInfo_GetTransfersParam proto.InternalMessageInfo

func (m *GetTransfersParam) GetIn() bool {
	if m != nil {
		return m.In
	}
	return false
}

func (m *GetTransfersParam) GetOut() bool {
	if m != nil {
		return m.Out
	}
	return false
}

func (m *GetTransfersParam) GetPending() bool {
	if m != nil {
		return m.Pending
	}
	return false
}

func (m *GetTransfersParam) GetFailed() bool {
	if m != nil {
		return m.Failed
	}
	return false
}

func (m *GetTransfersParam) GetPool() bool {
	if m != nil {
		return m.Pool
	}
	return false
}

func (m *GetTransfersParam) GetFilterByHeight() bool {
	if m != nil {
		return m.FilterByHeight
	}
	return false
}

func (m *GetTransfersParam) GetMinHeight() uint64 {
	if m != nil {
		return m.MinHeight
	}
	return 0
}

func (m *GetTransfersParam) GetMaxHeight() uint64 {
	if m != nil {
		return m.MaxHeight
	}
	return 0
}

type GetTransfersResult struct {
	Desc                 []*TransferDetails `protobuf:"bytes,1,rep,name=desc,proto3" json:"desc,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *GetTransfersResult) Reset()         { *m = GetTransfersResult{} }
func (m *GetTransfersResult) String() string { return proto.CompactTextString(m) }
func (*GetTransfersResult) ProtoMessage()    {}
func (*GetTransfersResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ae4206faa118e98, []int{1}
}

func (m *GetTransfersResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetTransfersResult.Unmarshal(m, b)
}
func (m *GetTransfersResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetTransfersResult.Marshal(b, m, deterministic)
}
func (m *GetTransfersResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetTransfersResult.Merge(m, src)
}
func (m *GetTransfersResult) XXX_Size() int {
	return xxx_messageInfo_GetTransfersResult.Size(m)
}
func (m *GetTransfersResult) XXX_DiscardUnknown() {
	xxx_messageInfo_GetTransfersResult.DiscardUnknown(m)
}

var xxx_messageInfo_GetTransfersResult proto.InternalMessageInfo

func (m *GetTransfersResult) GetDesc() []*TransferDetails {
	if m != nil {
		return m.Desc
	}
	return nil
}

func init() {
	proto.RegisterType((*GetTransfersParam)(nil), "model.GetTransfersParam")
	proto.RegisterType((*GetTransfersResult)(nil), "model.GetTransfersResult")
}

func init() { proto.RegisterFile("get_transfers.proto", fileDescriptor_3ae4206faa118e98) }

var fileDescriptor_3ae4206faa118e98 = []byte{
	// 250 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x90, 0xcd, 0x4a, 0xc3, 0x40,
	0x14, 0x85, 0xc9, 0x4f, 0xd3, 0x7a, 0x85, 0x52, 0xaf, 0x10, 0x06, 0x41, 0x08, 0x5d, 0x05, 0x17,
	0x59, 0xe8, 0x0b, 0x88, 0x08, 0xba, 0x94, 0xe0, 0x3e, 0x4c, 0xcd, 0x4d, 0x3a, 0x30, 0x99, 0x09,
	0x93, 0x29, 0xb4, 0xcf, 0xeb, 0x8b, 0x88, 0x37, 0x19, 0xe8, 0xee, 0x9e, 0xef, 0x3b, 0xb3, 0x98,
	0x03, 0xf7, 0x3d, 0xf9, 0xc6, 0x3b, 0x69, 0xa6, 0x8e, 0xdc, 0x54, 0x8d, 0xce, 0x7a, 0x8b, 0xab,
	0xc1, 0xb6, 0xa4, 0x1f, 0xf2, 0xc0, 0x9b, 0x96, 0xbc, 0x54, 0x7a, 0xd1, 0xfb, 0xdf, 0x08, 0xee,
	0x3e, 0xc8, 0x7f, 0x87, 0x57, 0x5f, 0xd2, 0xc9, 0x01, 0xb7, 0x10, 0x2b, 0x23, 0xa2, 0x22, 0x2a,
	0x37, 0x75, 0xac, 0x0c, 0xee, 0x20, 0xb1, 0x27, 0x2f, 0x62, 0x06, 0xff, 0x27, 0x0a, 0x58, 0x8f,
	0x64, 0x5a, 0x65, 0x7a, 0x91, 0x30, 0x0d, 0x11, 0x73, 0xc8, 0x3a, 0xa9, 0x34, 0xb5, 0x22, 0x65,
	0xb1, 0x24, 0x44, 0x48, 0x47, 0x6b, 0xb5, 0x58, 0x31, 0xe5, 0x1b, 0x4b, 0xd8, 0x75, 0x4a, 0x7b,
	0x72, 0xcd, 0xe1, 0xd2, 0x1c, 0x49, 0xf5, 0x47, 0x2f, 0x32, 0xf6, 0xdb, 0x99, 0xbf, 0x5d, 0x3e,
	0x99, 0xe2, 0x23, 0xc0, 0xa0, 0x4c, 0xe8, 0xac, 0x8b, 0xa8, 0x4c, 0xeb, 0x9b, 0x41, 0x99, 0x2b,
	0x2d, 0xcf, 0x41, 0x6f, 0x16, 0x2d, 0xcf, 0xb3, 0xde, 0xbf, 0x02, 0x5e, 0x7f, 0xb2, 0xa6, 0xe9,
	0xa4, 0x3d, 0x3e, 0x41, 0xda, 0xd2, 0xf4, 0x23, 0xa2, 0x22, 0x29, 0x6f, 0x9f, 0xf3, 0x8a, 0x97,
	0xaa, 0x42, 0xeb, 0x7d, 0xde, 0xa9, 0xe6, 0xce, 0x21, 0xe3, 0xb9, 0x5e, 0xfe, 0x02, 0x00, 0x00,
	0xff, 0xff, 0x9b, 0xbe, 0x1d, 0xda, 0x64, 0x01, 0x00, 0x00,
}
