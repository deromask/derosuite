// Code generated by protoc-gen-go. DO NOT EDIT.
// source: transfer_details.proto

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

type TransferDetails struct {
	Txid                 string         `protobuf:"bytes,1,opt,name=txid,proto3" json:"txid,omitempty"`
	PaymentId            string         `protobuf:"bytes,2,opt,name=payment_id,json=paymentId,proto3" json:"payment_id,omitempty"`
	BlockHeight          uint64         `protobuf:"varint,3,opt,name=block_height,json=blockHeight,proto3" json:"block_height,omitempty"`
	BlockTopoheight      int64          `protobuf:"varint,4,opt,name=block_topoheight,json=blockTopoheight,proto3" json:"block_topoheight,omitempty"`
	Amount               uint64         `protobuf:"varint,5,opt,name=amount,proto3" json:"amount,omitempty"`
	Fee                  uint64         `protobuf:"varint,6,opt,name=fee,proto3" json:"fee,omitempty"`
	UnlockTime           uint64         `protobuf:"varint,7,opt,name=unlock_time,json=unlockTime,proto3" json:"unlock_time,omitempty"`
	Destinations         []*Destination `protobuf:"bytes,8,rep,name=Destinations,proto3" json:"Destinations,omitempty"`
	SecretTxKey          string         `protobuf:"bytes,9,opt,name=secret_tx_key,json=secretTxKey,proto3" json:"secret_tx_key,omitempty"`
	Type                 string         `protobuf:"bytes,10,opt,name=type,proto3" json:"type,omitempty"`
	Timestamp            uint64         `protobuf:"varint,11,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *TransferDetails) Reset()         { *m = TransferDetails{} }
func (m *TransferDetails) String() string { return proto.CompactTextString(m) }
func (*TransferDetails) ProtoMessage()    {}
func (*TransferDetails) Descriptor() ([]byte, []int) {
	return fileDescriptor_5d0593309f86c8f2, []int{0}
}

func (m *TransferDetails) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransferDetails.Unmarshal(m, b)
}
func (m *TransferDetails) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransferDetails.Marshal(b, m, deterministic)
}
func (m *TransferDetails) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransferDetails.Merge(m, src)
}
func (m *TransferDetails) XXX_Size() int {
	return xxx_messageInfo_TransferDetails.Size(m)
}
func (m *TransferDetails) XXX_DiscardUnknown() {
	xxx_messageInfo_TransferDetails.DiscardUnknown(m)
}

var xxx_messageInfo_TransferDetails proto.InternalMessageInfo

func (m *TransferDetails) GetTxid() string {
	if m != nil {
		return m.Txid
	}
	return ""
}

func (m *TransferDetails) GetPaymentId() string {
	if m != nil {
		return m.PaymentId
	}
	return ""
}

func (m *TransferDetails) GetBlockHeight() uint64 {
	if m != nil {
		return m.BlockHeight
	}
	return 0
}

func (m *TransferDetails) GetBlockTopoheight() int64 {
	if m != nil {
		return m.BlockTopoheight
	}
	return 0
}

func (m *TransferDetails) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *TransferDetails) GetFee() uint64 {
	if m != nil {
		return m.Fee
	}
	return 0
}

func (m *TransferDetails) GetUnlockTime() uint64 {
	if m != nil {
		return m.UnlockTime
	}
	return 0
}

func (m *TransferDetails) GetDestinations() []*Destination {
	if m != nil {
		return m.Destinations
	}
	return nil
}

func (m *TransferDetails) GetSecretTxKey() string {
	if m != nil {
		return m.SecretTxKey
	}
	return ""
}

func (m *TransferDetails) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *TransferDetails) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func init() {
	proto.RegisterType((*TransferDetails)(nil), "model.TransferDetails")
}

func init() { proto.RegisterFile("transfer_details.proto", fileDescriptor_5d0593309f86c8f2) }

var fileDescriptor_5d0593309f86c8f2 = []byte{
	// 288 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x90, 0xc1, 0x4e, 0xc2, 0x40,
	0x10, 0x86, 0x53, 0x0a, 0x68, 0xa7, 0x18, 0x70, 0x0e, 0x64, 0x63, 0x34, 0x56, 0x4e, 0xf5, 0xc2,
	0x41, 0x13, 0x9f, 0x80, 0x83, 0xc6, 0x5b, 0xd3, 0x7b, 0x53, 0xe8, 0x20, 0x1b, 0x68, 0x77, 0xd3,
	0x1d, 0x12, 0xfa, 0xcc, 0xbe, 0x84, 0x61, 0xb6, 0x11, 0xbd, 0xcd, 0x7c, 0xff, 0x3f, 0x93, 0x99,
	0x1f, 0xe6, 0xdc, 0x96, 0x8d, 0xdb, 0x52, 0x5b, 0x54, 0xc4, 0xa5, 0x3e, 0xb8, 0xa5, 0x6d, 0x0d,
	0x1b, 0x1c, 0xd5, 0xa6, 0xa2, 0xc3, 0xdd, 0x6d, 0x45, 0x8e, 0x75, 0x53, 0xb2, 0x36, 0x8d, 0x57,
	0x16, 0xdf, 0x03, 0x98, 0xe6, 0xfd, 0xd0, 0xca, 0xcf, 0x20, 0xc2, 0x90, 0x4f, 0xba, 0x52, 0x41,
	0x12, 0xa4, 0x51, 0x26, 0x35, 0x3e, 0x00, 0xd8, 0xb2, 0xab, 0xa9, 0xe1, 0x42, 0x57, 0x6a, 0x20,
	0x4a, 0xd4, 0x93, 0x8f, 0x0a, 0x9f, 0x60, 0xb2, 0x3e, 0x98, 0xcd, 0xbe, 0xd8, 0x91, 0xfe, 0xda,
	0xb1, 0x0a, 0x93, 0x20, 0x1d, 0x66, 0xb1, 0xb0, 0x77, 0x41, 0xf8, 0x0c, 0x33, 0x6f, 0x61, 0x63,
	0x4d, 0x6f, 0x1b, 0x26, 0x41, 0x1a, 0x66, 0x53, 0xe1, 0xf9, 0x2f, 0xc6, 0x39, 0x8c, 0xcb, 0xda,
	0x1c, 0x1b, 0x56, 0x23, 0xd9, 0xd3, 0x77, 0x38, 0x83, 0x70, 0x4b, 0xa4, 0xc6, 0x02, 0xcf, 0x25,
	0x3e, 0x42, 0x7c, 0x6c, 0xfc, 0x56, 0x5d, 0x93, 0xba, 0x12, 0x05, 0x3c, 0xca, 0x75, 0x4d, 0xf8,
	0x06, 0x93, 0xd5, 0xe5, 0x69, 0xa7, 0xae, 0x93, 0x30, 0x8d, 0x5f, 0x70, 0x29, 0x81, 0x2c, 0xff,
	0x48, 0xd9, 0x3f, 0x1f, 0x2e, 0xe0, 0xc6, 0xd1, 0xa6, 0x25, 0x2e, 0xf8, 0x54, 0xec, 0xa9, 0x53,
	0x91, 0xbc, 0x1c, 0x7b, 0x98, 0x9f, 0x3e, 0xa9, 0x93, 0x9c, 0x3a, 0x4b, 0x0a, 0xfa, 0x9c, 0x3a,
	0x4b, 0x78, 0x0f, 0xd1, 0xf9, 0x12, 0xc7, 0x65, 0x6d, 0x55, 0x2c, 0xe7, 0x5c, 0xc0, 0x7a, 0x2c,
	0xa1, 0xbf, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0x07, 0x90, 0xdb, 0x09, 0xa8, 0x01, 0x00, 0x00,
}
