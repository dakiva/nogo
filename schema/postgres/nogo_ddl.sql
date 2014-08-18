CREATE TABLE role (
       role_id          bigserial PRIMARY KEY,
       role_name        text UNIQUE NOT NULL,
       permission_mask  int NOT NULL
);

CREATE TABLE role_members (
       role_id            bigint NOT NULL,
       principal_sid      text NOT NULL,
       CONSTRAINT pk__role_members PRIMARY KEY(role_id, principal_sid),
       CONSTRAINT fk_role_members_role_id FOREIGN KEY(role_id) REFERENCES role(role_id) ON DELETE CASCADE
);

CREATE INDEX ix_role_members_principal_sid ON role_members (
       principal_sid
);

CREATE TABLE groups (
       group_id     bigserial PRIMARY KEY,
       group_name   text UNIQUE NOT NULL
);

CREATE TABLE group_members (
       group_id            bigint NOT NULL,
       principal_sid       text NOT NULL,
       CONSTRAINT pk_group_members PRIMARY KEY(group_id, principal_sid),
       CONSTRAINT fk_group_members_group_id FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE INDEX ix_group_members_principal_sid ON group_members (
       principal_sid
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
       permission_mask int NOT NULL,
       CONSTRAINT ix_acl_entry_acl_resource_id_sid UNIQUE(acl_resource_id, sid),
       CONSTRAINT fk_acl_entry_acl_resource_id FOREIGN KEY(acl_resource_id) REFERENCES secure_resource(resource_id) ON DELETE CASCADE,
       CONSTRAINT fk_acl_entry_sid FOREIGN KEY(sid) REFERENCES sid(sid_id)
);
