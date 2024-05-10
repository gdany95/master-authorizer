create table invite_token (tenant_id integer not null, expiry_date timestamp(6) with time zone, token varchar(255) not null, roles jsonb, primary key (token));
create table multi_user_role (multi_user_id integer not null, role_id bigint not null, primary key (multi_user_id, role_id));
create table multi_user (id serial not null, display_name varchar(255), password text, principals jsonb unique, primary key (id));
create table role (is_system BOOLEAN DEFAULT false not null, tenant_id integer, id bigserial not null, name varchar(255) not null, authorities jsonb, primary key (id));
create table tenant (id serial not null, name varchar(255) not null unique, primary key (id));
alter table if exists invite_token add constraint FK6x6h4w9cef44hils12c0y437o foreign key (tenant_id) references tenant;
alter table if exists multi_user_role add constraint FKpel6jbw3rpjne84ve1kd29tdb foreign key (role_id) references role;
alter table if exists multi_user_role add constraint FK6owxgh4kp9rcs08mmgeiiv95c foreign key (multi_user_id) references multi_user;
alter table if exists role add constraint FKf08bg28kh2xfj27r4ejarvv8x foreign key (tenant_id) references tenant;

insert into tenant(id, name) values(1, 'Default Tenant');
insert into multi_user(id, display_name, password, principals) values(1, 'Default User', '{noop}admin', '["admin"]');
insert into role(is_system, tenant_id, id, name, authorities) values(true, 1, 1, 'SysAdmin', '["CREATE_TENANTS","MODIFY_TENANT","VIEW_USERS","CREATE_USERS","DELETE_USERS","VIEW_ROLES","CREATE_ROLES","MODIFY_ROLES","DELETE_ROLES","MODIFY_USER_ROLES"]');
insert into multi_user_role(multi_user_id, role_id) values(1, 1);