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
	// given
	create := Permission(1)
	update := Permission(2)
	r := NewRole("testRole", create)
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindAll").Return([]Role{r}, nil)

	p := &mockPrincipal{roleNames: []string{"testRole"}}
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)

	// when
	err := aclService.VerifyRoleAccess(p, update)

	// then
	assert.NotNil(t, err)

	err = aclService.VerifyRoleAccess(p, create)
	assert.Nil(t, err)
}

func TestVerifyAdminRoleAccess(t *testing.T) {
	// given
	update := Permission(2)
	r := NewAdminRole("testAdminRole", EmptyPermissionMask)
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindAll").Return([]Role{r}, nil)
	p := &mockPrincipal{roleNames: []string{"testAdminRole"}}

	// when

	// verify with allowAdmin on
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)
	err := aclService.VerifyRoleAccess(p, update)

	// then
	assert.Nil(t, err)

	// verify with allowAdmin off
	aclService = NewAccessControlStrategy(nil, mockRoleRepo, false)
	err = aclService.VerifyRoleAccess(p, update)
	assert.NotNil(t, err)
}

func TestVerifyResourceACL(t *testing.T) {
	// given
	create := Permission(1)
	update := Permission(2)
	p := &mockPrincipal{sid: "id", roleNames: []string{}}
	acl := NewACL()
	acl.AddACE(NewACE("id", create))
	resource := &mockResource{nativeId: "id", acl: acl}
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindAll").Return([]Role{}, nil)
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)

	// when
	err := aclService.VerifyResourceAccess(p, update, resource)

	// then
	assert.NotNil(t, err)

	err = aclService.VerifyResourceAccess(p, create, resource)
	assert.Nil(t, err)

	// role repo should not be interacted with when verifying ACLs for non-admins
	mockRoleRepo.AssertExpectations(t)
}

func TestVerifyInheritedResourceACL(t *testing.T) {
	// given
	create := Permission(1)
	update := Permission(2)
	p := &mockPrincipal{sid: "id", roleNames: []string{}}

	parentACL := NewACL()
	parentACL.AddACE(NewACE("id", update))
	parentResource := &mockResource{nativeId: "parentId", acl: parentACL}
	acl := NewACL()
	acl.AddACE(NewACE("id", create))
	resource := &mockResource{nativeId: "id", acl: acl, parent: parentResource}
	aclService := NewAccessControlStrategy(nil, nil, false)

	// when
	// verify with inherit off
	err := aclService.VerifyResourceAccess(p, update, resource)
	assert.NotNil(t, err)

	// then
	// verify with inherit on
	resource.inheritACL = true
	err = aclService.VerifyResourceAccess(p, update, resource)
	assert.Nil(t, err)

	err = aclService.VerifyResourceAccess(p, create, resource)
	assert.Nil(t, err)
}

func TestVerifyAdminResourceAccess(t *testing.T) {
	// given
	create := Permission(1)
	r := NewAdminRole("testAdminRole", EmptyPermissionMask)
	p := &mockPrincipal{sid: "id", roleNames: []string{"testAdminRole"}}
	resource := &mockResource{nativeId: "id", acl: NewACL()}
	mockRoleRepo := new(mockRoleRepository)
	mockRoleRepo.On("FindAll").Return([]Role{r}, nil)

	// when
	// verify with allowAdmin on
	aclService := NewAccessControlStrategy(nil, mockRoleRepo, true)
	err := aclService.VerifyResourceAccess(p, create, resource)
	assert.Nil(t, err)

	// then
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

func (this *mockPrincipal) GetId() string {
	return this.id
}

func (this *mockPrincipal) GetSid() string {
	return this.sid
}

func (this *mockPrincipal) GetRoleNames() []string {
	return this.roleNames
}

// mock resource
type mockResource struct {
	nativeId   string
	acl        ACL
	parent     SecureResource
	owner      string
	inheritACL bool
}

func (this *mockResource) GetNativeId() string {
	return this.nativeId
}

func (this *mockResource) GetACL() (ACL, error) {
	return this.acl, nil
}

func (this *mockResource) GetParentResource() SecureResource {
	return this.parent
}

func (this *mockResource) GetOwnerSid() string {
	return this.owner
}

func (this *mockResource) InheritsParentACL() bool {
	return this.inheritACL
}

// mock role repository
type mockRoleRepository struct {
	mock.Mock
}

func (this *mockRoleRepository) FindAll() ([]Role, error) {
	args := this.Mock.Called()
	return args.Get(0).([]Role), args.Error(1)
}

func (this *mockRoleRepository) FindRole(roleName string) (Role, error) {
	args := this.Mock.Called(roleName)
	return args.Get(0).(Role), args.Error(1)
}

func (this *mockRoleRepository) CreateRole(role Role) error {
	args := this.Mock.Called(role)
	return args.Error(0)
}

func (this *mockRoleRepository) UpdateRole(role Role) error {
	args := this.Mock.Called(role)
	return args.Error(0)
}

func (this *mockRoleRepository) DeleteRole(roleName string) error {
	args := this.Mock.Called(roleName)
	return args.Error(0)
}

// mock resource repository
type mockSecureResourceRepository struct {
	mock.Mock
}

func (this *mockSecureResourceRepository) FindResource(nativeResourceId string) (SecureResource, error) {
	args := this.Mock.Called(nativeResourceId)
	return args.Get(0).(SecureResource), args.Error(1)
}

func (this *mockSecureResourceRepository) CreateResource(resource SecureResource) error {
	args := this.Mock.Called(resource)
	return args.Error(0)
}

func (this *mockSecureResourceRepository) UpdateResource(resource SecureResource) error {
	args := this.Mock.Called(resource)
	return args.Error(0)
}

func (this *mockSecureResourceRepository) DeleteResource(nativeResourceId string) error {
	args := this.Mock.Called(nativeResourceId)
	return args.Error(0)
}
