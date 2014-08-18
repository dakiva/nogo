CREATE TABLE role (
       role_id    bigserial PRIMARY KEY,
       role_name  text UNIQUE NOT NULL
);

CREATE TABLE permission (
       permission_id    bigserial PRIMARY KEY,
       permission_name  text UNIQUE NOT NULL
);

CREATE TABLE role_permission (
       role_id               bigint NOT NULL,
       permission_id         bigint NOT NULL,
       CONSTRAINT pk_role_permission PRIMARY KEY(role_id, permission_id),
       CONSTRAINT fk_role_permission_role_id FOREIGN KEY(role_id) REFERENCES role(role_id) ON DELETE CASCADE,
       CONSTRAINT fk_role_permission_permission_id FOREIGN KEY(permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE
);

CREATE TABLE principal_role (
       principal_id         text NOT NULL,
       role_id              bigint NOT NULL,
       CONSTRAINT pk_principal_role PRIMARY KEY(principal_id, role_id),
       CONSTRAINT fk_principal_role_role_id FOREIGN KEY(role_id) REFERENCES role(role_id) ON DELETE CASCADE
);

CREATE TABLE groups (
       group_id     bigserial PRIMARY KEY,
       group_name   text UNIQUE NOT NULL
);

CREATE TABLE principal_groups (
       principal_id           text NOT NULL,
       group_id               bigint NOT NULL,
       CONSTRAINT pk_principal_groups PRIMARY KEY(principal_id, group_id),
       CONSTRAINT fk_principal_groups_group_id FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE INDEX ix_principal_groups_group_id ON principal_groups (
       group_id
);

CREATE TABLE sid (
       sid_id    bigserial PRIMARY KEY,
       principal boolean NOT NULL,
       sid text  UNIQUE NOT NULL
);

CREATE TABLE secure_resource (
       resource_id           bigserial PRIMARY KEY,
       native_resource_id    text UNIQUE NOT NULL,
       parent_resource_id    bigint,
       owner_id bigint       NOT NULL,
       inherit_parent_acl    boolean NOT NULL,
       CONSTRAINT fk_secure_resource_parent_resource_id FOREIGN KEY(parent_resource_id) REFERENCES secure_resource(resource_id),
       CONSTRAINT fk_secure_resource_owner_id FOREIGN KEY(owner_id) REFERENCES sid(sid_id)
);

CREATE TABLE acl_entry(
       id              bigserial PRIMARY KEY,
       acl_resource_id bigint NOT NULL,
       sid             bigint NOT NULL,
       permission_id   bigint NOT NULL,
       CONSTRAINT ix_acl_entry_acl_resource_id_sid_permission_id UNIQUE(acl_resource_id, sid, permission_id),
       CONSTRAINT fk_acl_entry_acl_resource_id FOREIGN KEY(acl_resource_id) REFERENCES secure_resource(resource_id) ON DELETE CASCADE,
       CONSTRAINT fk_acl_entry_sid FOREIGN KEY(sid) REFERENCES sid(sid_id),
       CONSTRAINT fk_acl_entry_permission FOREIGN KEY(permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE
);

INSERT INTO permission (permission_name) VALUES
   ('Create'), ('Read'), ('Update'), ('Delete')
;
