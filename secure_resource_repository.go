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

// A repository for managing secure resource acls. The use of resource Id here refers to an external identifier for the resource.
type SecureResourceRepository interface {
	// Returns the secure resource for the given resource id. Returns an error if the object id is invalid, or if the secure resource could not be retrieved.
	FindResource(nativeResourceId string) (SecureResource, error)
	// Creates a new secure resource for the given resource id and, optionally a parent id. Returns an error if the resourceId is invalid, or if the resource already contains an ACL.
	CreateResource(resource SecureResource) error
	// Updates an ACL for the given resource. Returns an error if the resourceId is invalid, or if the resource does not contain an ACL.
	UpdateResource(resource SecureResource) error
	// Deletes an ACL for the given resource. Returns an error if the resourceId is invalid, or if the resource does not contain an ACL.
	DeleteResource(nativeResourceId string) error
}
