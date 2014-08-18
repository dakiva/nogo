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

// Represents a specific capability defined by the system or mode of resource access that can be granted to Principals by way of Role assignment or resource ACLs.
type Permission int

// Represents a user of the system. A principal simply has an ID and 0 or more roles. The principal's authorization is defined by the set of roles associated to the principal.
type Principal interface {
	// Returns the ID of the principal. This is generally an ID assigned by the system to uniquely identify the user. Must not return an empty value.
	GetId() string
	// Returns the security identifier of the principal. This value is used in mapping access controls.
	GetSid() string
	// Returns a slice of distinct role names granting the principal authorized access to specific system capabilities. May return an empty value.
	GetRoleNames() []string
}

// A role is a named set of permissions authorizing a principal access to specific capabilities defined by the system or modes of access to data managed by the system.
type Role interface {
	// Returns the unique name of the Role. Must not return an empty value.
	GetName() string
	// Returns true if this Role is considered an administrator. Administrators are generally a unique case, in that they have access to everything in the system. For the majority of roles, the value returned should be false. This flag is useful when evaluating access to resources. Administrators often have full access to all resources.
	IsAdmin() bool
	// Returns true if the Role contains the following permission. If IsAdmin returns true, implementations may choose to simply bypass calling this function, allowing admins full access. Returns an error if an error occurs resolving the permission.
	HasPermission(permission Permission) (bool, error)
}

// Creates a new role with a specific set of permissions
func NewRole(name string, mask Permission) Role {
	return &defaultRole{name: name, permissionMask: mask, isAdmin: false}
}

// Creates a new admin role.
func NewAdminRole(name string, mask Permission) Role {
	return &defaultRole{name: name, permissionMask: mask, isAdmin: true}
}

type defaultRole struct {
	name           string
	permissionMask Permission
	isAdmin        bool
}

func (this *defaultRole) GetName() string {
	return this.name
}

func (this *defaultRole) IsAdmin() bool {
	return this.isAdmin
}

func (this *defaultRole) HasPermission(permission Permission) (bool, error) {
	val := (this.permissionMask&permission != 0)
	return val, nil
}
