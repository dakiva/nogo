nogo
====

An authorization library for Go.

[![wercker status](https://app.wercker.com/status/e8832169d39f8306d6ff136fc75da59a/m "wercker status")](https://app.wercker.com/project/bykey/e8832169d39f8306d6ff136fc75da59a)

Overview
========
Nogo provides easy to use role-based access controls for servers as well as access control lists (ACLs) support for defining access to resources.

DISCLAIMER: This is a work in progress and has not yet been locked down. Expect the APIs to change until otherwise noted.

Installation
============
Make sure you have a working Go environment. The core library does not have any external dependencies. To run the unit tests, however, the [testify](https://github.com/stretchr/testify) library is required.

To install, run:
   ```
   go get github.com/dakiva/nogo
   ```
Getting Started
===============
There are two types of access checks that nogo supports:

* Role based access - Providing authorization controls over system capabilities (often restricts functionality in the service tier).
* Access Control lists - Provides authorization controls over system resources.

Concepts
========
* Principal - A defined user of the system who may attempt to access specific system capabilities or resources.
* Permission - A controlled system capability (or mode of access when defined for resources).
* Role - A named set of permissions used to grant a prinicipal access to a specific system capability/service.
* ACE - AccessControlEntry granting a principal a specific mode of access to a resource.
* ACL - AccessControlList A list of entries granting principals permissions to a resource.
* SecureResource - A resource whose access is controlled by an ACL. SecureResources may be nested allowing for access controls to be inherited when verifying access.

Role based access (RBAC)
========================
Nogo is straightforward to get going out of the box.

* Create specific permissions that represent system level capabilities that you want controlled.
* Define your roles.
* Create a RoleRepository instance. You may use the provided map backed repository, or roll out your own repository.
* Instantiate an AccessControlStrategy backed by the RoleRepository created.
* If you have the concept of a User/Principal in your system, adapt to the Principal interface and map your roles to your users accordingly.
```
       const (
          Create = 1 << iota
          Read
          Update
          Delete
          CoolPermission
       )
       
       var ACStrategy nogo.AccessControlStrategy
       func init() {
               var userRole = nogo.NewRole("User", CoolPermission)
               roleRepository := nogo.NewMapBackedRepository()
               roleRepository.CreateRole(userRole)
               // pass true to allow admin roles full access to the system
               ACStrategy := nogo.NewAccessControlStrategy(nil, roleRepository, true)
       }
  
       // ....elsewhere in some service.....
       if err := AcStrategy.VerifyRoleAccess(principal, CoolPermission); err != nil {
             // Access denied!!
             // handle this
       } else {
             // access granted... continue
       }
```
Access Control Lists (ACLs)
==========================
For in memory support for existing resources that already encapsulate specific access-related details (such as ownership, etc), adapt your resource to the SecureResource interface and return an ACL.

Most systems, however, will likely need to persist ACLs and thus will need to implement the SecureResourceRepository for loading and returning SecureResources from a database. Support for this is not here yet...For now, you will need to implement your own repository and provide an instance of the repository when constructing the AccessControlStrategy.

Collaboration
=============
This library is still really early in development and has not had a "locked" release yet. This is a great time to provide suggestions, ideas. Pull requests are welcome.

* TODO
 - use int64 for permission mask. This is already supported in the DB.

About
=====
This library is written by Daniel Akiva and is licensed under the apache-2.0 license.
