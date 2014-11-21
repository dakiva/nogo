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

	"github.com/dakiva/dbx"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

var testdb *sqlx.DB
var queryMap dbx.QueryMap

func init() {
	testdb = dbx.MustInitializeTestDB("migrations")
	queryMap = dbx.MustLoadNamedQueries("queries/nogo_queries.json")
}

func TestRoleCreation(t *testing.T) {
	// given
	tx, _ := testdb.Beginx()
	defer tx.Rollback()
	repo := NewDBBackedRoleRepository(tx, queryMap)

	// when
	err := repo.CreateRole(NewRole("role1", 16))
	assert.Nil(t, err)
	err = repo.CreateRole(NewRole("role2", 16))
	assert.Nil(t, err)

	// then
	roles, err := repo.FindAll()
	assert.Nil(t, err)
	assert.Equal(t, 2, len(roles))
}

func TestRoleUpdate(t *testing.T) {
	// given
	tx, _ := testdb.Beginx()
	defer tx.Rollback()
	repo := NewDBBackedRoleRepository(tx, queryMap)
	roleName := "role"

	// when
	repo.CreateRole(NewRole(roleName, 16))
	err := repo.UpdateRole(NewRole(roleName, 32))

	// then
	assert.Nil(t, err)
	role, err := repo.FindRole(roleName)
	assert.Nil(t, err)
	assert.Equal(t, roleName, role.GetName())
	val, err := role.HasPermission(32)
	assert.Nil(t, err)
	assert.True(t, val)
}

func TestRoleDeletion(t *testing.T) {
	// given
	tx, _ := testdb.Beginx()
	defer tx.Rollback()
	repo := NewDBBackedRoleRepository(tx, queryMap)
	roleName := "role"
	repo.CreateRole(NewRole(roleName, 16))

	// when
	err := repo.DeleteRole(roleName)

	// then
	assert.Nil(t, err)
	role, err := repo.FindRole(roleName)
	assert.Nil(t, err)
	assert.Nil(t, role)
}
