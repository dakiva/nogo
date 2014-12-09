nogo - An Authorization Library for Go
======================================

[![wercker status](https://app.wercker.com/status/e8832169d39f8306d6ff136fc75da59a/m "wercker status")](https://app.wercker.com/project/bykey/e8832169d39f8306d6ff136fc75da59a)

Overview
--------
Nogo provides easy to use role-based access controls for servers as well as access control lists (ACLs) support for defining access to resources.

Installation
------------
Make sure you have a working Go environment. The core library does not have any external dependencies. To run the unit tests, however, the [testify](https://github.com/stretchr/testify) library is required.

To install, run:
   ```
   go get github.com/dakiva/nogo
   ```
Functionality
=============
There are two types of access checks that nogo supports:

* Role Based Access - Provides authorization controls over system capabilities via permissions (often restricts functionality in the service tier).
* Access Control Lists - Provides authorization controls over system resources (often arranged in a hierarchy).

Terminology
-----------
* Principal - A defined user of the system who may attempt to access specific system capabilities or resources.
* Permission - A controlled system capability (or mode of access when defined for resources).
* Role - A named set of permissions used to grant a principal access to a specific system capability/service.
* ACE - AccessControlEntry granting a principal a specific mode of access to a resource.
* ACL - AccessControlList A list of entries granting principals permissions to a resource.
* SecureResource - A resource whose access is controlled by an ACL. SecureResources may be nested allowing for access controls to be inherited when verifying access.

Getting Started with Role Based Access Control (RBAC)
=====================================================
Nogo is straightforward to get going out of the box.

* Create specific permissions that represent system level capabilities that you want controlled.
(Suggestion: Be sure to start with the four CRUD permissions even if you will not be taking advantage of resource control to start. You may decide to light it up later.)
```
       const (
          Create nogo.Permission = 1 << iota
          Read
          Update
          Delete
          PurchaseRequest
          PurchaseApprove
          PurchaseConfirm
          PurchaseCancel
       )
```
       
* Define your roles and associate them with permissions. For this you'll need a RoleRepository instance. You may use the provided map-backed repository, or roll your own repository.

```
       func init() {
               var adminRole = nogo.NewAdminRole("Admin", 0)
               var employeeRole = nogo.NewRole("Employee", PurchaseRequest|PurchaseCancel)
               var managerRole = nogo.NewRole("Manager", PurchaseApprove|PurchaseCancel)
               var receivingClerkRole = nogo.NewRole("Receiving Clerk", PurchaseConfirm)
               roleRepository := nogo.NewMapBackedRepository()
               roleRepository.CreateRole(adminRole)
               roleRepository.CreateRole(employeeRole)
               roleRepository.CreateRole(managerRole)
               roleRepository.CreateRole(receivingClerkRole)
               ...
       }
```

* Next, instantiate an AccessControlStrategy that refers to your RoleRepository.

```
       var ACStrategy nogo.AccessControlStrategy

       func init() {
               ...
               // A nil Resource Repository is acceptable if not taking advantage of resource control
               // A third argument of true allows admin roles full access to the system
               ACStrategy := nogo.NewAccessControlStrategy(nil, roleRepository, true)
       }
```

* Make sure your user object adheres to the Principal interface by implementing the GetId(), GetSid(), and GetRoleNames() methods.

```
       func (this *MyUser) GetId() string {
           return "bob@example.com"
       }
       func (this *MyUser) GetSid() string {
           return "1234"
       }
       func (this *MyUser) GetRoleNames() []string {
           return []string{"Manager","Supervisor"}
       }

```

* To check if a user has a certain permission, call the strategy's VerifyRoleAccess() method. If it returns a nil error, then permission is granted.

```
  
       // ....elsewhere in some service.....
       if err := AcStrategy.VerifyRoleAccess(principal, PurchaseRequest); err != nil {
             // Access denied!!
             // handle this
       } else {
             // access granted... continue
       }
```

Getting Started with Access Control Lists (ACLs)
================================================
You may wish to take advantage of the optional features for securing system resources.

* Make sure that enough permissions are defined to cover the range of resource controls that you want to apply. That will undoubtedly include the four basic CRUD permissions (see above) as well as perhaps a Share permission.

* Make sure your system resource objects adhere to the SecureResource interface by implementing the following methods: GetNativeId(), GetACL(), GetParentResource(), GetOwnerSid(), and InheritsParentACL().

* In order to persist ACLs, you will also need to implement the SecureResourceRepository for loading and returning SecureResources from a database and then provide an instance of the repository when constructing the AccessControlStrategy. (Unlike the MapBackedRepository for role-based access control, there is no generic support for an ACL repository.)


Collaboration
=============
This library is still really early in development and has not had a "locked" release yet. This is a great time to provide suggestions, ideas. Pull requests are welcome.

About
=====
This library is written by *Daniel Akiva (dakiva)* and is licensed under the apache-2.0 license.

Additional contributers:

* *Craig Jones (polyglot-jones)*
