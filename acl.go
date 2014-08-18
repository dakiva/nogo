// Copyright 2014 Daniel Akiva

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nogo

import (
	"errors"
	"math"
)

const (
	EmptyPermissionMask Permission = 0
)

// A representation of an access control list.
type ACL interface {
	// Returns a slice of access control entries. May return an empty value.
	GetACEs() ([]ACE, error)
	// Adds an access control entry to the list. Returns an error if the entry was not successfully added.
	AddACE(ace ACE) error
	// Removes an access control entry from the list. Returns an error if the entry was not successfully removed, or if the entry could not be located.
	RemoveACE(ace ACE) error
	// Returns an access control entry associated with the sid. May return an empty value. Returns an error if the principal could not be looked up.
	GetACEForSid(sid string) (ACE, error)
}

// An access control entry definition that can be referenced in resource ACLs.
type ACE interface {
	// Returns the SID of the principal that is granted access. Must not return an empty value.
	GetSid() string
	// Returns the permissions. Must not return an empty array.
	GetPermissions() []Permission
	// Returns true if the ACE contains the permission. Returns an error if the permission check could not be performed.
	HasPermission(permission Permission) (bool, error)
}

// A secure resource is defined as containing an access control list that restricts modes of access to itself.
type SecureResource interface {
	// returns the native (external) id for the resource.
	GetNativeId() string
	// returns the acl for the resource. Must not return an empty value. Returns an error if the acl could not be retrieved.
	GetACL() (ACL, error)
	// Returns the parent resource. May return nil if the resource does not have a parent.
	GetParentResource() SecureResource
	// Returns the sid of the principal who owns this resource.
	GetOwnerSid() string
	// Returns true if this resource inherits the ACL from its parent.
	InheritsParentACL() bool
}

// Creates a new access control list
func NewACL() ACL {
	return &defaultACL{aces: make(map[string]ACE)}
}

type defaultACL struct {
	aces map[string]ACE
}

func (this *defaultACL) GetACEs() ([]ACE, error) {
	ret := make([]ACE, 0, len(this.aces))
	for _, v := range this.aces {
		ret = append(ret, v)
	}
	return ret, nil
}

func (this *defaultACL) AddACE(ace ACE) error {
	if _, ok := this.aces[ace.GetSid()]; ok {
		return errors.New("The entry already exists in this ACL.")
	}
	this.aces[ace.GetSid()] = ace
	return nil
}

func (this *defaultACL) RemoveACE(ace ACE) error {
	if _, ok := this.aces[ace.GetSid()]; ok {
		delete(this.aces, ace.GetSid())
		return nil
	}
	return errors.New("Error removing ACE.")
}

func (this *defaultACL) GetACEForSid(sid string) (ACE, error) {
	if entry, ok := this.aces[sid]; ok {
		return entry, nil
	}
	return nil, nil
}

// Creates a control entry for the sid and set of permissions
func NewACE(sid string, mask Permission) ACE {
	return &defaultACE{sid, mask}
}

type defaultACE struct {
	sid            string
	permissionMask Permission
}

func (this *defaultACE) GetSid() string {
	return this.sid
}

func (this *defaultACE) GetPermissions() []Permission {
	permissions := make([]Permission, 0)
	pos := Permission(1)
	for pos < math.MaxInt32 {
		if this.permissionMask&(pos) != 0 {
			permissions = append(permissions, pos)
		}
		pos = pos << 1
	}
	return permissions
}

func (this *defaultACE) HasPermission(permission Permission) (bool, error) {
	val := (this.permissionMask&permission != 0)
	return val, nil
}
