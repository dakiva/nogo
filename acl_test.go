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
	ace := NewACE("id", Create)
	ace2 := NewACE("id", Update)
	acl := NewACL()

	acl.AddACE(ace)
	acl.AddACE(ace2)

	aces, err := acl.GetACEs()
	assert.Equal(t, 2, len(aces))
	assert.Equal(t, ace, aces[0])
	assert.Equal(t, ace2, aces[1])
	assert.Nil(t, err)
}

func TestAclAddDuplicateACE(t *testing.T) {
	ace := NewACE("id", Create)
	dupe := NewACE("id", Create)
	acl := NewACL()

	acl.AddACE(ace)
	err := acl.AddACE(dupe)

	assert.NotNil(t, err)
	aces, _ := acl.GetACEs()
	assert.Equal(t, 1, len(aces))
}

func TestValidRemoveACEs(t *testing.T) {
	ace := NewACE("id", Create)
	ace2 := NewACE("id", Update)
	ace3 := NewACE("id2", Create)
	acl := NewACL()
	acl.AddACE(ace)
	acl.AddACE(ace2)
	acl.AddACE(ace3)

	err := acl.RemoveACE(ace)
	assert.Nil(t, err)
	err = acl.RemoveACE(ace3)
	assert.Nil(t, err)

	aces, _ := acl.GetACEs()
	assert.Equal(t, 1, len(aces))
	assert.Equal(t, ace2, aces[0])
}

func TestRemoveNonExistentACE(t *testing.T) {
	ace := NewACE("id", Create)
	acl := NewACL()

	err := acl.RemoveACE(ace)

	assert.NotNil(t, err)
}

func TestGetACEsForPrincipal(t *testing.T) {
	ace := NewACE("id", Create)
	ace2 := NewACE("id", Update)
	ace3 := NewACE("id2", Create)
	acl := NewACL()

	acl.AddACE(ace)
	acl.AddACE(ace2)
	acl.AddACE(ace3)

	aces, err := acl.GetACEsForSid("id")
	assert.Equal(t, 2, len(aces))
	assert.Nil(t, err)

	aces, err = acl.GetACEsForSid("id2")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(aces))

	aces, err = acl.GetACEsForSid("id3")
	assert.NotNil(t, err)
}

func TestAuthorized(t *testing.T) {
	ace := NewACE("id", Create)
	acl := NewACL()

	acl.AddACE(ace)

	isAuth, err := acl.HasPermission("id", Update)
	assert.False(t, isAuth)
	assert.Nil(t, err)
	isAuth, err = acl.HasPermission("id", Create)
	assert.True(t, isAuth)
	assert.Nil(t, err)
}
