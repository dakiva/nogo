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

// A repository for managing roles.
type RoleRepository interface {
	// Finds and returns all roles managed by this repository or an error if there was an error finding roles.
	FindAll() ([]Role, error)
	// Returns the role for the given role name or an error if an error occurred while retrieving the role.
	FindRole(roleName string) (Role, error)
	// Creates a new role. Returns an error if the role could not be created, or already exists.
	CreateRole(role Role) error
	// Updates an existing role. Returns an error if the role could not be updated, or if the role does not exist.
	UpdateRole(role Role) error
	// Removes an existing role. Returns an error if the role could not be deleted, or if the role does not exist.
	DeleteRole(roleName string) error
}
