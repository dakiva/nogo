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
	"fmt"
	"math"
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

func TestDefaultACEHasPermissionBoundaries(t *testing.T) {
	ace := NewACE("00000000-0000-0000-0000-000000000000", Permission(1))
	isAuth, err := ace.HasPermission(Permission(-1))
	assert.False(t, isAuth, "should not have permissions")
	assert.Nil(t, err, "should be no error")

	ace = NewACE("00000000-0000-0000-0000-000000000000", Permission(math.MaxInt32))
	isAuth, err = ace.HasPermission(Permission(-1))
	assert.False(t, isAuth, "should not have permissions")
	assert.Nil(t, err, "should be no error")

	isAuth, err = ace.HasPermission(Permission(1))
	assert.True(t, isAuth, "should have permissions")
	assert.Nil(t, err, "should be no error")

	isAuth, err = ace.HasPermission(Permission(1<<31 - 1))
	assert.True(t, isAuth, "should have permissions")
	assert.Nil(t, err, "should be no error")
}

func TestDefaultACEGetPermissions(t *testing.T) {
	ace := NewACE("00000000-0000-0000-0000-000000000000", Permission(0))
	perms := ace.GetPermissions()
	assert.Equal(t, 0, len(perms), "should not have any permissions")

	ace = NewACE("00000000-0000-0000-0000-000000000000", Permission(math.MaxInt32))
	perms = ace.GetPermissions()
	assert.Equal(t, 31, len(perms), "should have maximum permissions")
}

const N = 1000

// TestDefaultACEConcurrentAdd tries to concurrently add
// ACEs to the ACL. This should expose any data races when
// accessing the internal map.
func TestDefaultACEConcurrentAdd(t *testing.T) {
	acl := NewACL()
	done := make(chan struct{})

	for i := 0; i < N; i++ {
		go func(index int) {
			perm := Permission(index)
			ace := NewACE("id", perm)
			acl.AddACE(ace)
			done <- struct{}{}
		}(i)
	}

	//drain the done channel, can substitute with a WaitGroup
	for i := 0; i < N; i++ {
		<-done
	}

	aces, err := acl.GetACEs()
	assert.Nil(t, err, "there should be no error")
	assert.Equal(t, N, len(aces), "all ACEs should be accounted for")
}

// TestDefaultACEConcurrentRemove populates an ACL and then
// tries to concurrently remove the ACE entries. This should
// expose any data races while accessing the internal map.
func TestDefaultACEConcurrentRemove(t *testing.T) {
	acl := NewACL()
	done := make(chan struct{})
	aces := make([]ACE, 0, N)

	for i := 0; i < N; i++ {
		perm := Permission(i)
		ace := NewACE(fmt.Sprintf("sid-%d", i), perm)
		aces = append(aces, ace)
		acl.AddACE(ace)
	}

	for _, ace := range aces {
		go func(a ACE) {
			err := acl.RemoveACE(a)
			assert.Nil(t, err, "ACE record should be removeable")
			done <- struct{}{}
		}(ace)
	}

	//drain the done channel, can substitute with a WaitGroup
	for i := 0; i < N; i++ {
		<-done
	}

	aces, err := acl.GetACEs()
	assert.Nil(t, err, "there should be no error")
	assert.Equal(t, 0, len(aces), "all ACEs should be accounted for")
}
