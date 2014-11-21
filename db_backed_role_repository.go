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

import "github.com/dakiva/dbx"

type dbBackedRoleRepository struct {
	ctx      dbx.DBContext
	queryMap dbx.QueryMap
}

// Construct a new DB backed RoleRepository
func NewDBBackedRoleRepository(ctx dbx.DBContext, queryMap dbx.QueryMap) RoleRepository {
	return &dbBackedRoleRepository{ctx: ctx, queryMap: queryMap}
}

func (this *dbBackedRoleRepository) FindAll() ([]Role, error) {
	rows, err := this.ctx.NamedQuery(this.queryMap.Q("FindAllRoles"), map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]Role, 0)
	for rows.Next() {
		role := &defaultRole{}
		err = rows.StructScan(role)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (this *dbBackedRoleRepository) FindRole(roleName string) (Role, error) {
	rows, err := this.ctx.NamedQuery(this.queryMap.Q("FindRole"), map[string]interface{}{"role_name": roleName})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		role := &defaultRole{}
		err = rows.StructScan(role)
		if err != nil {
			return nil, err
		}
		return role, nil
	}
	return nil, nil
}

func (this *dbBackedRoleRepository) CreateRole(role Role) error {
	_, err := this.ctx.NamedExec(this.queryMap.Q("InsertRole"), role)
	if err != nil {
		return err
	}
	return nil
}

func (this *dbBackedRoleRepository) UpdateRole(role Role) error {
	_, err := this.ctx.NamedExec(this.queryMap.Q("UpdateRole"), role)
	if err != nil {
		return err
	}
	return nil
}

func (this *dbBackedRoleRepository) DeleteRole(roleName string) error {
	_, err := this.ctx.NamedExec(this.queryMap.Q("DeleteRole"), map[string]interface{}{"role_name": roleName})
	if err != nil {
		return err
	}
	return nil
}
