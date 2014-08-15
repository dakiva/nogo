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

func TestRoleAuthorization(t *testing.T) {
	role := NewRole("role", []Permission{Create})

	ret, err := role.HasPermission(Update)
	assert.False(t, ret)
	assert.Nil(t, err)

	ret, err = role.HasPermission(Create)
	assert.True(t, ret)
	assert.Nil(t, err)
}

func TestAdminAuthorization(t *testing.T) {
	role := NewAdminRole("role", nil)

	ret, err := role.HasPermission(Create)
	assert.False(t, ret)
	assert.Nil(t, err)
}
