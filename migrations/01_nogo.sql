-- +goose Up
CREATE TABLE role (
       role_id          bigserial,
       role_name        text NOT NULL,
       permission_mask  int NOT NULL,
       is_admin         boolean NOT NULL DEFAULT false,
       CONSTRAINT pk_role PRIMARY KEY(role_id)
);

CREATE UNIQUE INDEX ix_role_role_name ON role (
       role_name
);

CREATE TABLE role_member (
       role_id            bigint,
       principal_sid      text NOT NULL,
       CONSTRAINT pk_role_members PRIMARY KEY(role_id, principal_sid),
       CONSTRAINT fk_role_members_role_id FOREIGN KEY(role_id) REFERENCES role(role_id) ON DELETE CASCADE
);

CREATE INDEX ix_role_member_principal_sid ON role_member (
       principal_sid
);

CREATE TABLE secure_resource (
       secure_resource_id        bigserial,
       native_resource_id        text NOT NULL,
       parent_secure_resource_id bigint,
       owner_sid                 text NOT NULL,
       inherit_parent_acl        boolean NOT NULL DEFAULT true,
       CONSTRAINT pk_secure_resource PRIMARY KEY(secure_resource_id),
       CONSTRAINT fk_secure_resource_parent_secure_resource_id FOREIGN KEY(parent_secure_resource_id) REFERENCES secure_resource(secure_resource_id)
);

CREATE UNIQUE INDEX ix_secure_resource_native_resource_id ON secure_resource (
       native_resource_id
);

CREATE INDEX ix_secure_resource_owner_sid ON secure_resource (
       owner_sid
);

CREATE TABLE acl_entry (
       acl_entry_id       bigserial,
       secure_resource_id bigint NOT NULL,
       principal_sid      text NOT NULL,
       permission_mask    bigint NOT NULL,
       CONSTRAINT pk_acl_entry PRIMARY KEY(acl_entry_id),
       CONSTRAINT fk_acl_entry_acl_secure_resource_id FOREIGN KEY(secure_resource_id) REFERENCES secure_resource(secure_resource_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ix_acl_entry_secure_resource_id_principal_sid ON acl_entry (
       secure_resource_id,
       principal_sid
);

CREATE INDEX ix_acl_entry_principal_sid ON acl_entry (
       principal_sid
);
