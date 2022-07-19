// ref: MS-DTYP

package smb2

import (
	"strconv"
	"strings"
)

// AclRevision
// [MS-DTYP]: 2.4.4
const (
	ACL_REVISION = 2 << iota
	ACL_REVISION_DS
)

// AceType
// [MS-DTYP]: 2.4.4.1
const (
	ACE_TYPE_ACCESS_ALLOWED = 0 + iota
	ACE_TYPE_ACCESS_DENIED
	ACE_TYPE_SYSTEM_AUDIT
	ACE_TYPE_SYSTEM_ALARM
	ACE_TYPE_ACCESS_ALLOWED_COMPOUND
	ACE_TYPE_ACCESS_ALLOWED_OBJECT
	ACE_TYPE_ACCESS_DENIED_OBJECT
	ACE_TYPE_SYSTEM_AUDIT_OBJECT
	ACE_TYPE_SYSTEM_ALARM_OBJECT
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK
	ACE_TYPE_ACCESS_DENIED_CALLBACK
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT
	ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK
	ACE_TYPE_SYSTEM_ALARM_CALLBACK
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT
	ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT
	ACE_TYPE_SYSTEM_MANDATORY_LABEL
	ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE
	ACE_TYPE_SYSTEM_SCOPED_POLICY_ID
)

// AceFlags
// [MS-DTYP]: 2.4.4.1
const (
	ACE_FLAG_OBJECT_INHERIT = 1 << iota
	ACE_FLAG_CONTAINER_INHERIT
	ACE_FLAG_NO_PROPAGATE_INHERIT
	ACE_FLAG_INHERIT_ONLY
	ACE_FLAG_INHERITED

	ACE_FLAG_SUCCESSFUL_ACCESS = 0x40 << iota
	ACE_FLAG_FAILED_ACCESS
)

// Security descriptor control flags
// [MS-DTYP]: 2.4.6
const (
	SECURITY_DESCRIPTOR_OWNER_DEFAULTED = 1 << iota
	SECURITY_DESCRIPTOR_GROUP_DEFAULTED
	SECURITY_DESCRIPTOR_DACL_PRESENT
	SECURITY_DESCRIPTOR_DACL_DEFAULTED
	SECURITY_DESCRIPTOR_SACL_PRESENT
	SECURITY_DESCRIPTOR_SACL_DEFAULTED
	SECURITY_DESCRIPTOR_SERVER_SECURITY
	SECURITY_DESCRIPTOR_DACL_TRUSTED
	SECURITY_DESCRIPTOR_DACL_COMPUTED_INHERITANCE_REQUIRED
	SECURITY_DESCRIPTOR_SACL_COMPUTED_INHERITANCE_REQUIRED
	SECURITY_DESCRIPTOR_DACL_AUTO_INHERITED
	SECURITY_DESCRIPTOR_SACL_AUTO_INHERITED
	SECURITY_DESCRIPTOR_DACL_PROTECTED
	SECURITY_DESCRIPTOR_SACL_PROTECTED
	SECURITY_DESCRIPTOR_RM_CONTROL_VALID
	SECURITY_DESCRIPTOR_SELF_RELATIVE
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft *Filetime) Size() int {
	return 8
}

func (ft *Filetime) Encode(p []byte) {
	le.PutUint32(p[:4], ft.LowDateTime)
	le.PutUint32(p[4:8], ft.HighDateTime)
}

func (ft *Filetime) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func NsecToFiletime(nsec int64) (ft *Filetime) {
	nsec /= 100
	nsec += 116444736000000000

	return &Filetime{
		LowDateTime:  uint32(nsec & 0xffffffff),
		HighDateTime: uint32(nsec >> 32 & 0xffffffff),
	}
}

type FiletimeDecoder []byte

func (ft FiletimeDecoder) LowDateTime() uint32 {
	return le.Uint32(ft[:4])
}

func (ft FiletimeDecoder) HighDateTime() uint32 {
	return le.Uint32(ft[4:8])
}

func (ft FiletimeDecoder) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime())<<32 + int64(ft.LowDateTime())
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func (ft FiletimeDecoder) Decode() *Filetime {
	return &Filetime{
		LowDateTime:  ft.LowDateTime(),
		HighDateTime: ft.HighDateTime(),
	}
}

type Sid struct {
	Revision            uint8
	IdentifierAuthority uint64
	SubAuthority        []uint32
}

func (sid *Sid) String() string {
	list := make([]string, 0, 3+len(sid.SubAuthority))
	list = append(list, "S")
	list = append(list, strconv.Itoa(int(sid.Revision)))
	if sid.IdentifierAuthority < uint64(1<<32) {
		list = append(list, strconv.FormatUint(sid.IdentifierAuthority, 10))
	} else {
		list = append(list, "0x"+strconv.FormatUint(sid.IdentifierAuthority, 16))
	}
	for _, a := range sid.SubAuthority {
		list = append(list, strconv.FormatUint(uint64(a), 10))
	}
	return strings.Join(list, "-")
}

func (sid *Sid) Size() int {
	return 8 + len(sid.SubAuthority)*4
}

func (sid *Sid) Encode(p []byte) {
	p[0] = sid.Revision
	p[1] = uint8(len(sid.SubAuthority))
	for j := 0; j < 6; j++ {
		p[2+j] = byte(sid.IdentifierAuthority >> uint64(8*(6-j)))
	}
	off := 8
	for _, u := range sid.SubAuthority {
		le.PutUint32(p[off:off+4], u)
		off += 4
	}
}

type SidDecoder []byte

func (c SidDecoder) IsInvalid() bool {
	if len(c) < 8 {
		return true
	}

	if len(c) < 8+int(c.SubAuthorityCount())*4 {
		return true
	}

	return false
}

func (c SidDecoder) Revision() uint8 {
	return c[0]
}

func (c SidDecoder) SubAuthorityCount() uint8 {
	return c[1]
}

func (c SidDecoder) IdentifierAuthority() uint64 {
	var u uint64
	for j := 0; j < 6; j++ {
		u += uint64(c[7-j]) << uint64(8*j)
	}
	return u
}

func (c SidDecoder) SubAuthority() []uint32 {
	count := c.SubAuthorityCount()
	as := make([]uint32, count)
	off := 8
	for i := uint8(0); i < count; i++ {
		as[i] = le.Uint32(c[off : off+4])
		off += 4
	}
	return as
}

func (c SidDecoder) Decode() *Sid {
	return &Sid{
		Revision:            c.Revision(),
		IdentifierAuthority: c.IdentifierAuthority(),
		SubAuthority:        c.SubAuthority(),
	}
}

type SidEncoder struct {
	Sid string
}

func (c *SidEncoder) Size() int {
	if c.Sid == "" {
		return 0
	}

	return 8 + len(strings.Split(c.Sid, "-")[2:])*4
}

func (c *SidEncoder) Encode(p []byte) {

	var authority uint64
	s := strings.Split(c.Sid, "-")[2:]
	if strings.HasPrefix(s[0], "0x") {
		authority, _ = strconv.ParseUint(s[0], 16, 64)
	} else {
		authority, _ = strconv.ParseUint(s[0], 10, 64)
	}

	s = s[1:]
	var subAuthority []uint32

	for _, sub := range s {
		var temp uint64
		if strings.HasPrefix(sub, "0x") {
			temp, _ = strconv.ParseUint(sub, 16, 32)
		} else {
			temp, _ = strconv.ParseUint(sub, 10, 32)
		}

		subAuthority = append(subAuthority, uint32(temp))
	}

	sid := Sid{
		Revision:            0x01,
		IdentifierAuthority: authority,
		SubAuthority:        subAuthority,
	}

	sid.Encode(p)
}

type SecurityDescriptorDecoder []byte

func (c SecurityDescriptorDecoder) IsInvalid() bool {
	if len(c) < 20 {
		return true
	}

	expLength := 20
	if c.Revision() != 1 {
		return true
	}
	if c.OffsetOwner() != 0 {
		if c.OwnerSid().IsInvalid() {
			return true
		}
		expLength += c.OwnerSid().Decode().Size()
	}

	if c.OffsetGroup() != 0 {
		if c.GroupSid().IsInvalid() {
			return true
		}
		expLength += c.GroupSid().Decode().Size()
	}

	if c.OffsetSacl() != 0 {
		if c.Control()&SECURITY_DESCRIPTOR_SACL_PRESENT == 0 || c.Sacl().IsInvalid() {
			return true
		}
		expLength += int(c.Sacl().AclSize())
	} else if c.Control()&SECURITY_DESCRIPTOR_SACL_PRESENT != 0 {
		return true
	}

	if c.OffsetDacl() != 0 {
		if c.Control()&SECURITY_DESCRIPTOR_DACL_PRESENT == 0 || c.Dacl().IsInvalid() {
			return true
		}
		expLength += int(c.Dacl().AclSize())
	} else if c.Control()&SECURITY_DESCRIPTOR_DACL_PRESENT != 0 {
		return true
	}

	if len(c) != expLength {
		return true
	}

	return false
}

func (c SecurityDescriptorDecoder) Revision() uint8 {
	return c[0]
}

func (c SecurityDescriptorDecoder) Sbz1() uint8 {
	return c[1]
}

func (c SecurityDescriptorDecoder) Control() uint16 {
	return le.Uint16(c[2:4])
}

func (c SecurityDescriptorDecoder) OffsetOwner() uint32 {
	return le.Uint32(c[4:8])
}

func (c SecurityDescriptorDecoder) OffsetGroup() uint32 {
	return le.Uint32(c[8:12])
}

func (c SecurityDescriptorDecoder) OffsetSacl() uint32 {
	return le.Uint32(c[12:16])
}

func (c SecurityDescriptorDecoder) OffsetDacl() uint32 {
	return le.Uint32(c[16:20])
}

func (c SecurityDescriptorDecoder) OwnerSid() SidDecoder {
	return SidDecoder(c[c.OffsetOwner():])
}

func (c SecurityDescriptorDecoder) GroupSid() SidDecoder {
	return SidDecoder(c[c.OffsetGroup():])
}

func (c SecurityDescriptorDecoder) Sacl() ACLDecoder {
	if c.Control()&SECURITY_DESCRIPTOR_SACL_PRESENT == 0 {
		return nil
	}
	return ACLDecoder(c[c.OffsetSacl():])
}

func (c SecurityDescriptorDecoder) Dacl() ACLDecoder {
	if c.Control()&SECURITY_DESCRIPTOR_DACL_PRESENT == 0 {
		return nil
	}
	return ACLDecoder(c[c.OffsetDacl():])
}

type ACEAdditionalDataDecode []byte

type ACEDecoder []byte

func (c ACEDecoder) AceType() uint8 {
	return c[0]
}

func (c ACEDecoder) AceFlags() uint8 {
	return c[1]
}

func (c ACEDecoder) AceSize() uint16 {
	return le.Uint16(c[2:4])
}

func (c ACEDecoder) Mask() uint32 {
	return le.Uint32(c[4:8])
}

func (c ACEDecoder) Sid() SidDecoder {
	body := c[8:]
	switch c.AceType() {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		body = body[36:]
	}

	return SidDecoder(body)
}

func (c ACEDecoder) Flags() uint32 {
	switch c.AceType() {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		return le.Uint32(c[8:12])
	}

	return 0
}

func (c ACEDecoder) ObjectType() []byte {
	switch c.AceType() {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		return c[12:28]
	}

	return nil
}

func (c ACEDecoder) InheritedObjType() []byte {
	switch c.AceType() {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		return c[28:44]
	}

	return nil
}

func (c ACEDecoder) ApplicationData() []byte {

	switch c.AceType() {
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
		ACE_TYPE_ACCESS_DENIED_CALLBACK,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		body := c[8:]
		sid := SidDecoder(body).Decode()
		body = body[sid.Size():]

		if len(c.ObjectType()) > 0 {
			return c[36:]
		}
		return body
	}

	return nil
}

func (c ACEDecoder) AttributeData() []byte {
	switch c.AceType() {
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		body := c[8:]
		sid := SidDecoder(body).Decode()
		body = body[sid.Size():]

		return body
	}

	return nil
}

type ACL struct {
	AclRevision uint8
	Aces        []ACEDecoder
}

type ACLDecoder []byte

func (c ACLDecoder) Decode() ACL {
	return ACL{
		AclRevision: c.AclRevision(),
		Aces:        c.ACEs(),
	}
}

func (c ACLDecoder) IsInvalid() bool {
	return len(c) < 8 || len(c) != int(c.AclSize())
}

func (c ACLDecoder) AclRevision() uint8 {
	return c[0]
}

func (c ACLDecoder) Sbz1() uint8 {
	return c[1]
}

func (c ACLDecoder) AclSize() uint16 {
	return le.Uint16(c[2:4])
}

func (c ACLDecoder) AceCount() uint16 {
	return le.Uint16(c[4:6])
}

func (c ACLDecoder) Sbz2() uint16 {
	return le.Uint16(c[6:8])
}

func (c ACLDecoder) ACEs() []ACEDecoder {
	var aces []ACEDecoder
	var aceData ACEDecoder
	remaining := ACEDecoder(c[8:])

	count := int(c.AceCount())
	for i := 0; i < count; i++ {
		size := remaining.AceSize()
		aceData, remaining = remaining[:size], remaining[size:]

		aces = append(aces, aceData)
	}

	return aces
}

type ACLEncoder struct {
	ACEs []ACEEncoder
}

func (c *ACLEncoder) Size() int {
	size := 8
	for _, e := range c.ACEs {
		size += e.Size()
	}

	return size
}

func (c *ACLEncoder) ACLRevision() uint8 {
	for _, e := range c.ACEs {
		switch e.AceType {
		case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
			ACE_TYPE_ACCESS_DENIED_OBJECT,
			ACE_TYPE_SYSTEM_AUDIT_OBJECT,
			ACE_TYPE_SYSTEM_ALARM_OBJECT,
			ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
			return ACL_REVISION_DS
		}
	}

	return ACL_REVISION
}

func (c *ACLEncoder) Encode(p []byte) {
	p[0] = c.ACLRevision()
	p[1] = 0
	le.PutUint16(p[2:4], uint16(len(c.ACEs)))
	le.PutUint16(p[6:8], 0)

	offset := 8
	for _, e := range c.ACEs {
		size := e.Size()
		e.Encode(p[offset : offset+size])
		offset += size
	}

	le.PutUint16(p[4:6], uint16(offset))
}

type ACEEncoder struct {
	AceType  uint8
	AceFlags uint8
	Mask     uint32
	Sid      SidEncoder

	ApplicationData     []byte
	AttributeData       []byte
	Flags               uint32
	InheritedObjectType []byte
	ObjectType          []byte
}

func (c *ACEEncoder) Size() int {
	size := 8
	size += c.Sid.Size()
	switch c.AceType {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		size += 4 + 32
	}

	switch c.AceType {
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
		ACE_TYPE_ACCESS_DENIED_CALLBACK,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		size += len(c.ApplicationData)
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		size += len(c.AttributeData)
	}

	// AceSize must be multiple of 4
	if size%4 != 0 {
		size += 4 - size%4
	}
	return size
}

func (c *ACEEncoder) Encode(p []byte) {
	p[0] = c.AceType
	p[1] = c.AceFlags
	le.PutUint16(p[2:4], uint16(len(p)))
	le.PutUint32(p[4:8], c.Mask)

	body := p[8:]
	sidSize := c.Sid.Size()
	switch c.AceType {
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		ACE_TYPE_ACCESS_DENIED_OBJECT,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:

		le.PutUint32(body[0:4], c.Flags)
		copy(body[4:20], c.ObjectType)
		copy(body[20:36], c.InheritedObjectType)
		body = body[36:]
	}
	c.Sid.Encode(body)
	body = body[sidSize:]

	switch c.AceType {
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
		ACE_TYPE_ACCESS_DENIED_CALLBACK,
		ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
		ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_OBJECT,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK,
		ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		copy(body, c.ApplicationData)
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		copy(body, c.AttributeData)
	}
}

type SecurityDescriptorEncoder struct {
	Owner SidEncoder
	Group SidEncoder
	Flags uint16
	Sacl  ACLEncoder
	Dacl  ACLEncoder
}

func (c *SecurityDescriptorEncoder) Size() int {
	size := 20 + c.Owner.Size() + c.Group.Size()
	if c.Flags&SECURITY_DESCRIPTOR_SACL_PRESENT != 0 {
		size += c.Sacl.Size()
	}
	if c.Flags&SECURITY_DESCRIPTOR_DACL_PRESENT != 0 {
		size += c.Dacl.Size()
	}

	return size
}

func (c *SecurityDescriptorEncoder) Encode(p []byte) {
	//Revision
	p[0] = 1
	//Sbz1: SECURITY_DESCRIPTOR_RM_CONTROL_VALID is unsupported for now
	p[1] = 0
	c.Flags = c.Flags &^ SECURITY_DESCRIPTOR_RM_CONTROL_VALID
	//Control
	le.PutUint16(p[2:4], c.Flags)

	offset := 20

	//OffsetOwner
	if c.Owner.Sid != "" {
		le.PutUint32(p[4:8], 20)
		c.Owner.Encode(p[20:])
		offset += c.Owner.Size()
	}

	//OffsetGroup
	if c.Group.Sid != "" {
		le.PutUint32(p[8:12], uint32(offset))
		c.Group.Encode(p[offset:])
		offset += c.Group.Size()
	}

	//OffsetSacl
	if c.Flags&SECURITY_DESCRIPTOR_SACL_PRESENT != 0 {
		le.PutUint32(p[12:16], uint32(offset))
		c.Sacl.Encode(p[offset:])
		offset += c.Sacl.Size()
	}

	// OffsetDacl
	if c.Flags&SECURITY_DESCRIPTOR_DACL_PRESENT != 0 {
		le.PutUint32(p[12:16], uint32(offset))
		c.Dacl.Encode(p[offset:])
		offset += c.Dacl.Size()
	}
}
