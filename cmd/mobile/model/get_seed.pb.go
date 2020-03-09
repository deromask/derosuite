// Code generated by protoc-gen-go. DO NOT EDIT.
// source: get_seed.proto

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

type GetSeedParam struct {
	Lang                 string   `protobuf:"bytes,1,opt,name=lang,proto3" json:"lang,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetSeedParam) Reset()         { *m = GetSeedParam{} }
func (m *GetSeedParam) String() string { return proto.CompactTextString(m) }
func (*GetSeedParam) ProtoMessage()    {}
func (*GetSeedParam) Descriptor() ([]byte, []int) {
	return fileDescriptor_a827d11bcc8e3dfb, []int{0}
}

func (m *GetSeedParam) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetSeedParam.Unmarshal(m, b)
}
func (m *GetSeedParam) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetSeedParam.Marshal(b, m, deterministic)
}
func (m *GetSeedParam) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetSeedParam.Merge(m, src)
}
func (m *GetSeedParam) XXX_Size() int {
	return xxx_messageInfo_GetSeedParam.Size(m)
}
func (m *GetSeedParam) XXX_DiscardUnknown() {
	xxx_messageInfo_GetSeedParam.DiscardUnknown(m)
}

var xxx_messageInfo_GetSeedParam proto.InternalMessageInfo

func (m *GetSeedParam) GetLang() string {
	if m != nil {
		return m.Lang
	}
	return ""
}

type GetSeedResult struct {
	Seed                 string   `protobuf:"bytes,1,opt,name=seed,proto3" json:"seed,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetSeedResult) Reset()         { *m = GetSeedResult{} }
func (m *GetSeedResult) String() string { return proto.CompactTextString(m) }
func (*GetSeedResult) ProtoMessage()    {}
func (*GetSeedResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_a827d11bcc8e3dfb, []int{1}
}

func (m *GetSeedResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetSeedResult.Unmarshal(m, b)
}
func (m *GetSeedResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetSeedResult.Marshal(b, m, deterministic)
}
func (m *GetSeedResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetSeedResult.Merge(m, src)
}
func (m *GetSeedResult) XXX_Size() int {
	return xxx_messageInfo_GetSeedResult.Size(m)
}
func (m *GetSeedResult) XXX_DiscardUnknown() {
	xxx_messageInfo_GetSeedResult.DiscardUnknown(m)
}

var xxx_messageInfo_GetSeedResult proto.InternalMessageInfo

func (m *GetSeedResult) GetSeed() string {
	if m != nil {
		return m.Seed
	}
	return ""
}

func init() {
	proto.RegisterType((*GetSeedParam)(nil), "model.GetSeedParam")
	proto.RegisterType((*GetSeedResult)(nil), "model.GetSeedResult")
}

func init() { proto.RegisterFile("get_seed.proto", fileDescriptor_a827d11bcc8e3dfb) }

var fileDescriptor_a827d11bcc8e3dfb = []byte{
	// 105 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4b, 0x4f, 0x2d, 0x89,
	0x2f, 0x4e, 0x4d, 0x4d, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0xcd, 0xcd, 0x4f, 0x49,
	0xcd, 0x51, 0x52, 0xe2, 0xe2, 0x71, 0x4f, 0x2d, 0x09, 0x4e, 0x4d, 0x4d, 0x09, 0x48, 0x2c, 0x4a,
	0xcc, 0x15, 0x12, 0xe2, 0x62, 0xc9, 0x49, 0xcc, 0x4b, 0x97, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x0c,
	0x02, 0xb3, 0x95, 0x94, 0xb9, 0x78, 0xa1, 0x6a, 0x82, 0x52, 0x8b, 0x4b, 0x73, 0x4a, 0x40, 0x8a,
	0x40, 0x26, 0xc1, 0x14, 0x81, 0xd8, 0x49, 0x6c, 0x60, 0x63, 0x8d, 0x01, 0x01, 0x00, 0x00, 0xff,
	0xff, 0x8d, 0x7b, 0x99, 0x11, 0x68, 0x00, 0x00, 0x00,
}
