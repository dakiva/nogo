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
	"testing"

	"github.com/stretchr/testify/assert"
)

func CreateRoleTest(t *testing.T) {
	// given
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRoleRepository()

	// when
	err := repo.CreateRole(r)

	// then
	assert.Nil(t, err)
}

func CreateDuplicateRole(t *testing.T) {
	// given
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	r2 := NewRole("testRole", update)
	repo := NewMapBackedRoleRepository()

	// when
	err := repo.CreateRole(r)
	err = repo.CreateRole(r2)

	// then
	assert.NotNil(t, err)
}

func FindNonexistantRolesTest(t *testing.T) {
	// given
	repo := NewMapBackedRoleRepository()

	// when
	role, err := repo.FindRole("testRole")

	// then
	assert.Nil(t, err)
	assert.Nil(t, role)
}

func FindAllTest(t *testing.T) {
	// given
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	r2 := NewRole("testRole2", update)
	repo := NewMapBackedRoleRepository()
	repo.CreateRole(r)
	repo.CreateRole(r2)

	// when
	roles, err := repo.FindAll()

	// then
	assert.Nil(t, err)
	assert.Equal(t, 2, len(roles))
	assert.Equal(t, "testRole", roles[0].GetName())
	hasPermission, err := roles[0].HasPermission(create)
	assert.True(t, hasPermission)
	assert.Equal(t, "testRole2", roles[1].GetName())
	hasPermission, err = roles[1].HasPermission(update)
	assert.True(t, hasPermission)
}

func FindRoleTest(t *testing.T) {
	// given
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRoleRepository()
	repo.CreateRole(r)

	// when
	role, err := repo.FindRole("testRole")

	// then
	assert.Nil(t, err)
	assert.Equal(t, "testRole", role.GetName())
	hasPermission, err := role.HasPermission(create)
	assert.True(t, hasPermission)
}

func UpdateRoleTest(t *testing.T) {
	// given
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	repo := NewMapBackedRoleRepository()
	repo.CreateRole(r)

	// when
	r = NewRole("testRole", update)
	err := repo.UpdateRole(r)

	// then
	assert.Nil(t, err)
	role, _ := repo.FindRole("testRole")
	hasPermission, err := role.HasPermission(update)
	assert.True(t, hasPermission)
}

func UpdateNonExistantRoleTest(t *testing.T) {
	// given
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRoleRepository()

	// when
	err := repo.UpdateRole(r)

	// then
	assert.NotNil(t, err)
}

func DeleteRoleTest(t *testing.T) {
	// given
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRoleRepository()
	repo.CreateRole(r)

	// when
	err := repo.DeleteRole("testrole")

	// then
	assert.Nil(t, err)
	role, _ := repo.FindRole("testRole")
	assert.Nil(t, role)
}

func DeleteNonExistantRoleTest(t *testing.T) {
	// given
	repo := NewMapBackedRoleRepository()

	// when
	err := repo.DeleteRole("testRole")

	// then
	assert.NotNil(t, err)
}
