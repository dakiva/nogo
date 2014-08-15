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
	"fmt"
)

// Definition of specific authorized modes of access to a resource
const (
	Create Permission = "Create"
	Read              = "Read"
	Update            = "Update"
	Delete            = "Delete"
)

// A representation of an access control list.
type ACL interface {
	// Returns a slice of access control entries. May return an empty value.
	GetACEs() ([]ACE, error)
	// Adds an access control entry to the list. Returns an error if the entry was not successfully added.
	AddACE(ace ACE) error
	// Removes an access control entry from the list. Returns an error if the entry was not successfully removed, or if the entry could not be located.
	RemoveACE(ace ACE) error
	// Returns a slice of access control entries associated with the sid. May return an empty value. Returns an error if the principal is not referenced in the list.
	GetACEsForSid(sid string) ([]ACE, error)
	// Returns true if the sid is authorized to perform the specific mode of access defined by the permission. Returns an error if the authorization check could not be performed.
	HasPermission(sid string, permission Permission) (bool, error)
}

// An access control entry definition that can be referenced in resource ACLs.
type ACE interface {
	// Returns the SID of the principal that is granted access. Must not return an empty value.
	GetSid() string
	// Returns the permission. Must not return an empty value.
	GetPermission() Permission
}

// A secure resource is defined as containing an access control list that restricts modes of access to itself.
type SecureResource interface {
	// returns the native (external) id for the resource.
	GetNativeId() string
	// returns the acl for the resource. Must not return an empty value. Returns an error if the acl could not be retrieved.
	GetACL() (ACL, error)
	// returns the parent resource. May return nil if the resource does not have a parent.
	GetParentResource() SecureResource
}

func NewACL() ACL {
	return &defaultACL{aces: make(map[string][]ACE)}
}

type defaultACL struct {
	aces map[string][]ACE
}

func (d *defaultACL) GetACEs() ([]ACE, error) {
	ret := make([]ACE, 0, 10)
	for _, v := range d.aces {
		ret = append(ret, v...)
	}
	return ret, nil
}

func (d *defaultACL) AddACE(ace ACE) error {
	if entries, ok := d.aces[ace.GetSid()]; ok {
		for _, e := range entries {
			if e.GetPermission() == ace.GetPermission() {
				return errors.New("The entry already exists in this ACL.")
			}
		}
		d.aces[ace.GetSid()] = append(entries, ace)
	} else {
		d.aces[ace.GetSid()] = []ACE{ace}
	}
	return nil
}

func (d *defaultACL) RemoveACE(ace ACE) error {
	if entries, ok := d.aces[ace.GetSid()]; ok {
		idx := -1
		for i, e := range entries {
			if e.GetPermission() == ace.GetPermission() {
				idx = i
				break
			}
		}
		if idx >= 0 {
			var aces []ACE
			if len(entries) > 1 {
				aces = append(aces, entries[0:idx]...)
				aces = append(aces, entries[idx+1:]...)
			} else {
				aces = []ACE{}
			}
			d.aces[ace.GetSid()] = aces
			return nil
		}
	}
	return errors.New("Error removing ACE.")
}

func (d *defaultACL) GetACEsForSid(sid string) ([]ACE, error) {
	if entries, ok := d.aces[sid]; ok {
		return entries, nil
	}
	return nil, errors.New(fmt.Sprintf("No aces exist for sid %v.", sid))
}

func (d *defaultACL) HasPermission(sid string, permission Permission) (bool, error) {
	if entries, ok := d.aces[sid]; ok {
		for _, v := range entries {
			if permission == v.GetPermission() {
				return true, nil
			}
		}
	}
	return false, nil
}

func NewACE(sid string, permission Permission) ACE {
	return &defaultACE{sid, permission}
}

type defaultACE struct {
	sid        string
	permission Permission
}

func (t *defaultACE) GetSid() string {
	return t.sid
}

func (t *defaultACE) GetPermission() Permission {
	return t.permission
}
