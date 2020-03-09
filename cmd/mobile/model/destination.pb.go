// Code generated by protoc-gen-go. DO NOT EDIT.
// source: destination.proto

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

type Destination struct {
	Amount               uint64   `protobuf:"varint,1,opt,name=amount,proto3" json:"amount,omitempty"`
	Address              string   `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	HumanAmount          string   `protobuf:"bytes,3,opt,name=humanAmount,proto3" json:"humanAmount,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Destination) Reset()         { *m = Destination{} }
func (m *Destination) String() string { return proto.CompactTextString(m) }
func (*Destination) ProtoMessage()    {}
func (*Destination) Descriptor() ([]byte, []int) {
	return fileDescriptor_a55fe39993114776, []int{0}
}

func (m *Destination) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Destination.Unmarshal(m, b)
}
func (m *Destination) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Destination.Marshal(b, m, deterministic)
}
func (m *Destination) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Destination.Merge(m, src)
}
func (m *Destination) XXX_Size() int {
	return xxx_messageInfo_Destination.Size(m)
}
func (m *Destination) XXX_DiscardUnknown() {
	xxx_messageInfo_Destination.DiscardUnknown(m)
}

var xxx_messageInfo_Destination proto.InternalMessageInfo

func (m *Destination) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *Destination) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *Destination) GetHumanAmount() string {
	if m != nil {
		return m.HumanAmount
	}
	return ""
}

func init() {
	proto.RegisterType((*Destination)(nil), "model.Destination")
}

func init() { proto.RegisterFile("destination.proto", fileDescriptor_a55fe39993114776) }

var fileDescriptor_a55fe39993114776 = []byte{
	// 117 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x4c, 0x49, 0x2d, 0x2e,
	0xc9, 0xcc, 0x4b, 0x2c, 0xc9, 0xcc, 0xcf, 0xd3, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0xcd,
	0xcd, 0x4f, 0x49, 0xcd, 0x51, 0x4a, 0xe4, 0xe2, 0x76, 0x41, 0xc8, 0x09, 0x89, 0x71, 0xb1, 0x25,
	0xe6, 0xe6, 0x97, 0xe6, 0x95, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0xb0, 0x04, 0x41, 0x79, 0x42, 0x12,
	0x5c, 0xec, 0x89, 0x29, 0x29, 0x45, 0xa9, 0xc5, 0xc5, 0x12, 0x4c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41,
	0x30, 0xae, 0x90, 0x02, 0x17, 0x77, 0x46, 0x69, 0x6e, 0x62, 0x9e, 0x23, 0x44, 0x1b, 0x33, 0x58,
	0x16, 0x59, 0x28, 0x89, 0x0d, 0x6c, 0xa1, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0x45, 0x28, 0xdb,
	0x10, 0x85, 0x00, 0x00, 0x00,
}