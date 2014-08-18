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
	"github.com/stretchr/testify/mock"
)

func TestVerifyRoleAccess(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindRoles", []string{"testRole"}).Return([]Role{r}, nil)

	p := &mockPrincipal{roleNames: []string{"testRole"}}
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)

	err := aclService.VerifyRoleAccess(p, update)
	assert.NotNil(t, err)

	err = aclService.VerifyRoleAccess(p, create)
	assert.Nil(t, err)
}

func TestVerifyAdminRoleAccess(t *testing.T) {
	update := Permission(2)
	r := NewAdminRole("testAdminRole", EmptyPermissionMask)
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindRoles", []string{"testAdminRole"}).Return([]Role{r}, nil)

	p := &mockPrincipal{roleNames: []string{"testAdminRole"}}

	// verify with allowAdmin on
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)
	err := aclService.VerifyRoleAccess(p, update)
	assert.Nil(t, err)

	// verify with allowAdmin off
	aclService = NewAccessControlStrategy(nil, mockRoleRepo, false)
	err = aclService.VerifyRoleAccess(p, update)
	assert.NotNil(t, err)
}

func TestVerifyResourceACL(t *testing.T) {
	create := Permission(1)
	update := Permission(2)
	p := &mockPrincipal{sid: "id", roleNames: []string{}}
	acl := NewACL()
	acl.AddACE(NewACE("id", create))
	resource := &mockResource{nativeId: "id", acl: acl}
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindRoles", []string{}).Return([]Role{}, nil)
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)

	err := aclService.VerifyResourceAccess(p, update, resource)
	assert.NotNil(t, err)

	err = aclService.VerifyResourceAccess(p, create, resource)
	assert.Nil(t, err)

	mockRoleRepo.AssertExpectations(t)
}

func TestVerifyAdminResourceAccess(t *testing.T) {
	create := Permission(1)
	r := NewAdminRole("testAdminRole", EmptyPermissionMask)
	p := &mockPrincipal{sid: "id", roleNames: []string{"testAdminRole"}}
	resource := &mockResource{nativeId: "id", acl: NewACL()}
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindRoles", []string{"testAdminRole"}).Return([]Role{r}, nil)

	// verify with allowAdmin on
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)
	err := aclService.VerifyResourceAccess(p, create, resource)
	assert.Nil(t, err)

	// verify with allowAdmin off
	aclService = NewAccessControlStrategy(nil, mockRoleRepo, false)
	err = aclService.VerifyResourceAccess(p, create, resource)
	assert.NotNil(t, err)
}

// mock principal
type mockPrincipal struct {
	id        string
	sid       string
	roleNames []string
}

func (m *mockPrincipal) GetId() string {
	return m.id
}

func (m *mockPrincipal) GetSid() string {
	return m.sid
}

func (m *mockPrincipal) GetRoleNames() []string {
	return m.roleNames
}

// mock resource
type mockResource struct {
	nativeId string
	acl      ACL
	parent   SecureResource
}

func (m *mockResource) GetNativeId() string {
	return m.nativeId
}

func (m *mockResource) GetACL() (ACL, error) {
	return m.acl, nil
}

func (m *mockResource) GetParentResource() SecureResource {
	return m.parent
}

// mock role repository
type mockRoleRepository struct {
	mock.Mock
}

func (m *mockRoleRepository) FindRoles(roleNames ...string) ([]Role, error) {
	args := m.Mock.Called(roleNames)
	return args.Get(0).([]Role), args.Error(1)
}

func (m *mockRoleRepository) CreateRole(role Role) error {
	args := m.Mock.Called(role)
	return args.Error(0)
}

func (m *mockRoleRepository) UpdateRole(role Role) error {
	args := m.Mock.Called(role)
	return args.Error(0)
}

func (m *mockRoleRepository) DeleteRole(roleName string) error {
	args := m.Mock.Called(roleName)
	return args.Error(0)
}

// mock resource repository
type mockSecureResourceRepository struct {
	mock.Mock
}

func (m *mockSecureResourceRepository) FindResource(nativeResourceId string) (SecureResource, error) {
	args := m.Mock.Called(nativeResourceId)
	return args.Get(0).(SecureResource), args.Error(1)
}

func (m *mockSecureResourceRepository) CreateResource(resource SecureResource) error {
	args := m.Mock.Called(resource)
	return args.Error(0)
}

func (m *mockSecureResourceRepository) UpdateResource(resource SecureResource) error {
	args := m.Mock.Called(resource)
	return args.Error(0)
}

func (m *mockSecureResourceRepository) DeleteResource(nativeResourceId string) error {
	args := m.Mock.Called(nativeResourceId)
	return args.Error(0)
}
