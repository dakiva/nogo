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

// This strategy encapsulates all logic surrounding access control checks. For RBAC and ACL checks, clients will generally interface with methods defined on this interface.
type AccessControlStrategy interface {
	// Handles all RBAC checks ensuring a principal is authorized to perform a system capability represented by the permission. Returns an error if the principal does not have access.
	VerifyRoleAccess(principal Principal, permission Permission) error
	// Handles all ACL checks ensuring a principal is authorized the specific mode of access for a resource.
	VerifyResourceAccess(principal Principal, permission Permission, secure SecureResource) error
	// Loads the resource for the id and handles all ACL checks ensuring a principal is authorized the specific mode of access for the resource.
	VerifyResourceAccessById(principal Principal, permission Permission, resourceId string) error
}

// Returns the default access control strategy implementation. If allowAdmin is true, all checks are bypassed for principals that have an admin role.
func NewAccessControlStrategy(resourceRepo SecureResourceRepository, roleRepo RoleRepository, allowAdmin bool) AccessControlStrategy {
	return &defaultAccessControlStrategy{resourceRepository: resourceRepo, roleRepository: roleRepo, allowFullAdminAccess: allowAdmin}
}

type defaultAccessControlStrategy struct {
	resourceRepository   SecureResourceRepository
	roleRepository       RoleRepository
	allowFullAdminAccess bool
}

func (this *defaultAccessControlStrategy) VerifyRoleAccess(principal Principal, permission Permission) error {
	roles, err := this.roleRepository.FindRoles(principal.GetRoleNames()...)
	if err != nil {
		return errors.New("Could not verify role access.")
	}
	for _, role := range roles {
		if this.allowFullAdminAccess && role.IsAdmin() {
			return nil
		}
		auth, err := role.HasPermission(permission)
		if err != nil {
			return errors.New(fmt.Sprintf("Principal %v does not have access", principal.GetId()))
		}
		if auth {
			return nil
		}
	}
	return errors.New(fmt.Sprintf("Principal %v does not have access", principal.GetId()))
}

func (this *defaultAccessControlStrategy) VerifyResourceAccess(principal Principal, permission Permission, resource SecureResource) error {
	owner := resource.GetOwnerSid()
	if (owner != "" && owner == principal.GetSid()) || (this.allowFullAdminAccess && this.isAdmin(principal)) {
		return nil
	}
	if isAuth, err := hasPermission(principal.GetSid(), permission, resource); isAuth && err == nil {
		return nil
	} else if err != nil {
		return err
	}
	parent := resource.GetParentResource()
	for resource.InheritsParentACL() && parent != nil {
		if isAuth, err := hasPermission(principal.GetSid(), permission, parent); isAuth && err == nil {
			return nil
		} else if err != nil {
			return err
		}
		resource = parent
		parent = resource.GetParentResource()
	}
	return errors.New(fmt.Sprintf("Principal %v does not have access to the resource %v.", principal.GetId(), resource.GetNativeId()))
}

func (this *defaultAccessControlStrategy) VerifyResourceAccessById(principal Principal, permission Permission, resourceId string) error {
	resource, err := this.resourceRepository.FindResource(resourceId)
	if err != nil {
		return err
	}
	return this.VerifyResourceAccess(principal, permission, resource)
}

func (this *defaultAccessControlStrategy) isAdmin(principal Principal) bool {
	roles, err := this.roleRepository.FindRoles(principal.GetRoleNames()...)
	if err == nil {
		for _, role := range roles {
			if role.IsAdmin() {
				return true
			}
		}
	}
	return false
}

func hasPermission(sid string, permission Permission, resource SecureResource) (bool, error) {
	acl, err := resource.GetACL()
	if err != nil {
		return false, err
	}
	ace, err := acl.GetACEForSid(sid)
	if err != nil {
		return false, err
	}
	if ace != nil {
		if isAuth, err := ace.HasPermission(permission); isAuth && err == nil {
			return true, nil
		} else if err != nil {
			return false, err
		}
	}
	return false, nil
}
