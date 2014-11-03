CREATE TABLE role (
       role_id          bigserial PRIMARY KEY,
       role_name        text UNIQUE NOT NULL,
       permission_mask  int NOT NULL
);

CREATE TABLE role_member (
       role_id            bigint NOT NULL,
       principal_sid      text NOT NULL,
       CONSTRAINT pk_role_members PRIMARY KEY(role_id, principal_sid),
       CONSTRAINT fk_role_members_role_id FOREIGN KEY(role_id) REFERENCES role(role_id) ON DELETE CASCADE
);

CREATE INDEX ix_role_member_principal_sid ON role_member (
       principal_sid
);

CREATE TABLE secure_resource (
       secure_resource_id        bigserial PRIMARY KEY,
       native_resource_id        text UNIQUE NOT NULL,
       parent_secure_resource_id bigint,
       owner_sid                 text,
       inherit_parent_acl        boolean NOT NULL DEFAULT true,
       CONSTRAINT fk_secure_resource_parent_secure_resource_id FOREIGN KEY(parent_resource_id) REFERENCES secure_resource(secure_resource_id)
);

CREATE INDEX ix_secure_resource_native_resource_id ON secure_resource (
       native_resource_id
);

CREATE INDEX ix_secure_resource_owner_sid ON secure_resource (
       owner_sid
);

CREATE TABLE acl_entry (
       id                 bigserial PRIMARY KEY,
       secure_resource_id bigint NOT NULL,
       principal_sid      text NOT NULL,
       permission_mask    int NOT NULL,
       CONSTRAINT ix_acl_entry_acl_secure_resource_id_sid UNIQUE(secure_resource_id, principal_sid),
       CONSTRAINT fk_acl_entry_acl_secure_resource_id FOREIGN KEY(secure_resource_id) REFERENCES secure_resource(secure_resource_id) ON DELETE CASCADE
);

CREATE INDEX ix_acl_entry_principal_sid ON acl_entry (
       principal_sid
);
