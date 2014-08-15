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

type mapBackedRoleRepository struct {
	roleMap map[string]Role
}

func NewMapBackedRepository() RoleRepository {
	return &mapBackedRoleRepository{roleMap: make(map[string]Role)}
}

func (h *mapBackedRoleRepository) FindRoles(roleNames ...string) ([]Role, error) {
	ret := make([]Role, 0)
	for _, name := range roleNames {
		if role, ok := h.roleMap[name]; ok {
			ret = append(ret, role)
		} else {
			return nil, errors.New(fmt.Sprintf("Could not find role %v", name))
		}
	}
	return ret, nil
}

func (h *mapBackedRoleRepository) CreateRole(role Role) error {
	if _, ok := h.roleMap[role.GetName()]; ok {
		return errors.New(fmt.Sprintf("Error creating role. Role %v already exists", role.GetName()))
	}
	h.roleMap[role.GetName()] = role
	return nil
}

func (h *mapBackedRoleRepository) UpdateRole(role Role) error {
	if _, ok := h.roleMap[role.GetName()]; ok {
		h.roleMap[role.GetName()] = role
		return nil
	}
	return errors.New(fmt.Sprintf("Error updating role. Role %v does not exist.", role.GetName()))
}

func (h *mapBackedRoleRepository) DeleteRole(roleName string) error {
	if _, ok := h.roleMap[roleName]; ok {
		delete(h.roleMap, roleName)
	}
	return errors.New(fmt.Sprintf("Error deleting role. Role %v does not exist.", roleName))
}
