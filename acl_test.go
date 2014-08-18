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

func TestAclAddACE(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	ace := NewACE("id", create|update)
	acl := NewACL()

	acl.AddACE(ace)

	aces, err := acl.GetACEs()
	assert.Nil(t, err)
	assert.Equal(t, 1, len(aces))
	assert.Equal(t, ace, aces[0])
}

func TestAclAddDuplicateACE(t *testing.T) {
	create := Permission(1)
	ace := NewACE("id", create)
	dupe := NewACE("id", create)
	acl := NewACL()

	acl.AddACE(ace)
	err := acl.AddACE(dupe)

	assert.NotNil(t, err)
	aces, _ := acl.GetACEs()
	assert.Equal(t, 1, len(aces))
}

func TestValidRemoveACEs(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	ace := NewACE("id", create|update)
	ace2 := NewACE("id2", create)
	acl := NewACL()
	acl.AddACE(ace)
	acl.AddACE(ace2)

	err := acl.RemoveACE(ace)
	assert.Nil(t, err)

	aces, _ := acl.GetACEs()
	assert.Equal(t, 1, len(aces))
	assert.Equal(t, ace2, aces[0])
}

func TestRemoveNonExistentACE(t *testing.T) {
	create := Permission(1)
	ace := NewACE("id", create)
	acl := NewACL()

	err := acl.RemoveACE(ace)

	assert.NotNil(t, err)
}

func TestGetACEsForPrincipal(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	ace := NewACE("id", create|update)
	ace2 := NewACE("id2", create)
	acl := NewACL()

	acl.AddACE(ace)
	acl.AddACE(ace2)

	storedAce, _ := acl.GetACEForSid("id")
	assert.Equal(t, ace, storedAce)

	storedAce, _ = acl.GetACEForSid("id2")
	assert.Equal(t, ace2, storedAce)

	storedAce, _ = acl.GetACEForSid("id3")
	assert.Nil(t, storedAce)
}

func TestAuthorized(t *testing.T) {
	create := Permission(1)
	update := Permission(2)

	ace := NewACE("id", create)

	isAuth, err := ace.HasPermission(update)
	assert.False(t, isAuth)
	assert.Nil(t, err)
	isAuth, err = ace.HasPermission(create)
	assert.True(t, isAuth)
	assert.Nil(t, err)
}
