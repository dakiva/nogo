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
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRepository()

	err := repo.CreateRole(r)

	assert.Nil(t, err)
}

func CreateDuplicateRole(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	r2 := NewRole("testRole", update)
	repo := NewMapBackedRepository()

	err := repo.CreateRole(r)
	err = repo.CreateRole(r2)

	assert.NotNil(t, err)
}

func FindNonexistantRolesTest(t *testing.T) {
	repo := NewMapBackedRepository()

	_, err := repo.FindRoles("testRole")
	assert.NotNil(t, err)
}

func FindRolesTest(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	r2 := NewRole("testRole2", update)
	repo := NewMapBackedRepository()
	repo.CreateRole(r)
	repo.CreateRole(r2)

	roles, err := repo.FindRoles("testRole", "testRole2")

	assert.Nil(t, err)
	assert.Equal(t, 2, len(roles))
	assert.Equal(t, "testRole", roles[0].GetName())
	hasPermission, err := roles[0].HasPermission(create)
	assert.True(t, hasPermission)
	assert.Equal(t, "testRole2", roles[1].GetName())
	hasPermission, err = roles[0].HasPermission(update)
	assert.True(t, hasPermission)
}

func UpdateRoleTest(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	repo := NewMapBackedRepository()
	repo.CreateRole(r)

	r = NewRole("testRole", update)
	err := repo.UpdateRole(r)

	assert.Nil(t, err)
	roles, _ := repo.FindRoles("testRole")
	hasPermission, err := roles[0].HasPermission(update)
	assert.True(t, hasPermission)
}

func UpdateNonExistantRoleTest(t *testing.T) {
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRepository()

	err := repo.UpdateRole(r)

	assert.NotNil(t, err)
}

func DeleteRoleTest(t *testing.T) {
	create := Permission(1)
	r := NewRole("testRole", create)
	repo := NewMapBackedRepository()
	repo.CreateRole(r)

	err := repo.DeleteRole("testrole")

	assert.Nil(t, err)
	_, err = repo.FindRoles("testRole")
	assert.NotNil(t, err)
}

func DeleteNonExistantRoleTest(t *testing.T) {
	repo := NewMapBackedRepository()

	err := repo.DeleteRole("testRole")

	assert.NotNil(t, err)
}
