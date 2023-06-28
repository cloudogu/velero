// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: Shared.proto

package generated

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{0}
}

type Stack struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Frames []*StackFrame `protobuf:"bytes,1,rep,name=frames,proto3" json:"frames,omitempty"`
}

func (x *Stack) Reset() {
	*x = Stack{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Stack) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Stack) ProtoMessage() {}

func (x *Stack) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Stack.ProtoReflect.Descriptor instead.
func (*Stack) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{1}
}

func (x *Stack) GetFrames() []*StackFrame {
	if x != nil {
		return x.Frames
	}
	return nil
}

type StackFrame struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	File     string `protobuf:"bytes,1,opt,name=file,proto3" json:"file,omitempty"`
	Line     int32  `protobuf:"varint,2,opt,name=line,proto3" json:"line,omitempty"`
	Function string `protobuf:"bytes,3,opt,name=function,proto3" json:"function,omitempty"`
}

func (x *StackFrame) Reset() {
	*x = StackFrame{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StackFrame) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StackFrame) ProtoMessage() {}

func (x *StackFrame) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StackFrame.ProtoReflect.Descriptor instead.
func (*StackFrame) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{2}
}

func (x *StackFrame) GetFile() string {
	if x != nil {
		return x.File
	}
	return ""
}

func (x *StackFrame) GetLine() int32 {
	if x != nil {
		return x.Line
	}
	return 0
}

func (x *StackFrame) GetFunction() string {
	if x != nil {
		return x.Function
	}
	return ""
}

type ResourceIdentifier struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Group     string `protobuf:"bytes,1,opt,name=group,proto3" json:"group,omitempty"`
	Resource  string `protobuf:"bytes,2,opt,name=resource,proto3" json:"resource,omitempty"`
	Namespace string `protobuf:"bytes,3,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Name      string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *ResourceIdentifier) Reset() {
	*x = ResourceIdentifier{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceIdentifier) ProtoMessage() {}

func (x *ResourceIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceIdentifier.ProtoReflect.Descriptor instead.
func (*ResourceIdentifier) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{3}
}

func (x *ResourceIdentifier) GetGroup() string {
	if x != nil {
		return x.Group
	}
	return ""
}

func (x *ResourceIdentifier) GetResource() string {
	if x != nil {
		return x.Resource
	}
	return ""
}

func (x *ResourceIdentifier) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *ResourceIdentifier) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type ResourceSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IncludedNamespaces []string `protobuf:"bytes,1,rep,name=includedNamespaces,proto3" json:"includedNamespaces,omitempty"`
	ExcludedNamespaces []string `protobuf:"bytes,2,rep,name=excludedNamespaces,proto3" json:"excludedNamespaces,omitempty"`
	IncludedResources  []string `protobuf:"bytes,3,rep,name=includedResources,proto3" json:"includedResources,omitempty"`
	ExcludedResources  []string `protobuf:"bytes,4,rep,name=excludedResources,proto3" json:"excludedResources,omitempty"`
	Selector           string   `protobuf:"bytes,5,opt,name=selector,proto3" json:"selector,omitempty"`
}

func (x *ResourceSelector) Reset() {
	*x = ResourceSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceSelector) ProtoMessage() {}

func (x *ResourceSelector) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceSelector.ProtoReflect.Descriptor instead.
func (*ResourceSelector) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{4}
}

func (x *ResourceSelector) GetIncludedNamespaces() []string {
	if x != nil {
		return x.IncludedNamespaces
	}
	return nil
}

func (x *ResourceSelector) GetExcludedNamespaces() []string {
	if x != nil {
		return x.ExcludedNamespaces
	}
	return nil
}

func (x *ResourceSelector) GetIncludedResources() []string {
	if x != nil {
		return x.IncludedResources
	}
	return nil
}

func (x *ResourceSelector) GetExcludedResources() []string {
	if x != nil {
		return x.ExcludedResources
	}
	return nil
}

func (x *ResourceSelector) GetSelector() string {
	if x != nil {
		return x.Selector
	}
	return ""
}

type OperationProgress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Completed      bool                   `protobuf:"varint,1,opt,name=completed,proto3" json:"completed,omitempty"`
	Err            string                 `protobuf:"bytes,2,opt,name=err,proto3" json:"err,omitempty"`
	NCompleted     int64                  `protobuf:"varint,3,opt,name=nCompleted,proto3" json:"nCompleted,omitempty"`
	NTotal         int64                  `protobuf:"varint,4,opt,name=nTotal,proto3" json:"nTotal,omitempty"`
	OperationUnits string                 `protobuf:"bytes,5,opt,name=operationUnits,proto3" json:"operationUnits,omitempty"`
	Description    string                 `protobuf:"bytes,6,opt,name=description,proto3" json:"description,omitempty"`
	Started        *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=started,proto3" json:"started,omitempty"`
	Updated        *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=updated,proto3" json:"updated,omitempty"`
}

func (x *OperationProgress) Reset() {
	*x = OperationProgress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_Shared_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OperationProgress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OperationProgress) ProtoMessage() {}

func (x *OperationProgress) ProtoReflect() protoreflect.Message {
	mi := &file_Shared_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OperationProgress.ProtoReflect.Descriptor instead.
func (*OperationProgress) Descriptor() ([]byte, []int) {
	return file_Shared_proto_rawDescGZIP(), []int{5}
}

func (x *OperationProgress) GetCompleted() bool {
	if x != nil {
		return x.Completed
	}
	return false
}

func (x *OperationProgress) GetErr() string {
	if x != nil {
		return x.Err
	}
	return ""
}

func (x *OperationProgress) GetNCompleted() int64 {
	if x != nil {
		return x.NCompleted
	}
	return 0
}

func (x *OperationProgress) GetNTotal() int64 {
	if x != nil {
		return x.NTotal
	}
	return 0
}

func (x *OperationProgress) GetOperationUnits() string {
	if x != nil {
		return x.OperationUnits
	}
	return ""
}

func (x *OperationProgress) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *OperationProgress) GetStarted() *timestamppb.Timestamp {
	if x != nil {
		return x.Started
	}
	return nil
}

func (x *OperationProgress) GetUpdated() *timestamppb.Timestamp {
	if x != nil {
		return x.Updated
	}
	return nil
}

var File_Shared_proto protoreflect.FileDescriptor

var file_Shared_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09,
	0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x07, 0x0a, 0x05, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x22, 0x36, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x12, 0x2d, 0x0a, 0x06,
	0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x67,
	0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2e, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x46, 0x72,
	0x61, 0x6d, 0x65, 0x52, 0x06, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x22, 0x50, 0x0a, 0x0a, 0x53,
	0x74, 0x61, 0x63, 0x6b, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x69, 0x6c,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x6c, 0x69, 0x6e,
	0x65, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x78, 0x0a,
	0x12, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0xea, 0x01, 0x0a, 0x10, 0x52, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x2e, 0x0a, 0x12,
	0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x12, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x12, 0x2e, 0x0a, 0x12,
	0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x12, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x12, 0x2c, 0x0a, 0x11,
	0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65,
	0x64, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x65, 0x78,
	0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18,
	0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x22, 0xb1, 0x02, 0x0a, 0x11, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6f,
	0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x63,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x72, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x65, 0x72, 0x72, 0x12, 0x1e, 0x0a, 0x0a, 0x6e, 0x43,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a,
	0x6e, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x6e, 0x54,
	0x6f, 0x74, 0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x6e, 0x54, 0x6f, 0x74,
	0x61, 0x6c, 0x12, 0x26, 0x0a, 0x0e, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x55,
	0x6e, 0x69, 0x74, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x55, 0x6e, 0x69, 0x74, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x34, 0x0a, 0x07,
	0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x07, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x65, 0x64, 0x12, 0x34, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x42, 0x35, 0x5a, 0x33, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x2d, 0x74, 0x61,
	0x6e, 0x7a, 0x75, 0x2f, 0x76, 0x65, 0x6c, 0x65, 0x72, 0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_Shared_proto_rawDescOnce sync.Once
	file_Shared_proto_rawDescData = file_Shared_proto_rawDesc
)

func file_Shared_proto_rawDescGZIP() []byte {
	file_Shared_proto_rawDescOnce.Do(func() {
		file_Shared_proto_rawDescData = protoimpl.X.CompressGZIP(file_Shared_proto_rawDescData)
	})
	return file_Shared_proto_rawDescData
}

var file_Shared_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_Shared_proto_goTypes = []interface{}{
	(*Empty)(nil),                 // 0: generated.Empty
	(*Stack)(nil),                 // 1: generated.Stack
	(*StackFrame)(nil),            // 2: generated.StackFrame
	(*ResourceIdentifier)(nil),    // 3: generated.ResourceIdentifier
	(*ResourceSelector)(nil),      // 4: generated.ResourceSelector
	(*OperationProgress)(nil),     // 5: generated.OperationProgress
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
}
var file_Shared_proto_depIdxs = []int32{
	2, // 0: generated.Stack.frames:type_name -> generated.StackFrame
	6, // 1: generated.OperationProgress.started:type_name -> google.protobuf.Timestamp
	6, // 2: generated.OperationProgress.updated:type_name -> google.protobuf.Timestamp
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_Shared_proto_init() }
func file_Shared_proto_init() {
	if File_Shared_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_Shared_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_Shared_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Stack); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_Shared_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StackFrame); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_Shared_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceIdentifier); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_Shared_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceSelector); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_Shared_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OperationProgress); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_Shared_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_Shared_proto_goTypes,
		DependencyIndexes: file_Shared_proto_depIdxs,
		MessageInfos:      file_Shared_proto_msgTypes,
	}.Build()
	File_Shared_proto = out.File
	file_Shared_proto_rawDesc = nil
	file_Shared_proto_goTypes = nil
	file_Shared_proto_depIdxs = nil
}
