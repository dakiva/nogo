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

func NewMapBackedRoleRepository() RoleRepository {
	return &mapBackedRoleRepository{roleMap: make(map[string]Role)}
}

func (this *mapBackedRoleRepository) FindAll() ([]Role, error) {
	ret := make([]Role, 0)
	for _, role := range this.roleMap {
		ret = append(ret, role)
	}
	return ret, nil
}

func (this *mapBackedRoleRepository) FindRole(roleName string) (Role, error) {
	if role, ok := this.roleMap[roleName]; ok {
		return role, nil
	}
	return nil, errors.New(fmt.Sprintf("Could not find role %v", roleName))
}

func (this *mapBackedRoleRepository) CreateRole(role Role) error {
	if _, ok := this.roleMap[role.GetName()]; ok {
		return errors.New(fmt.Sprintf("Error creating role. Role %v already exists", role.GetName()))
	}
	this.roleMap[role.GetName()] = role
	return nil
}

func (this *mapBackedRoleRepository) UpdateRole(role Role) error {
	if _, ok := this.roleMap[role.GetName()]; ok {
		this.roleMap[role.GetName()] = role
		return nil
	}
	return errors.New(fmt.Sprintf("Error updating role. Role %v does not exist.", role.GetName()))
}

func (this *mapBackedRoleRepository) DeleteRole(roleName string) error {
	if _, ok := this.roleMap[roleName]; ok {
		delete(this.roleMap, roleName)
	}
	return errors.New(fmt.Sprintf("Error deleting role. Role %v does not exist.", roleName))
}
