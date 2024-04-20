package ro.linic.cloud.master.authorizer.entity;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;

public enum Authority {
	MODIFY_TENANT,
	VIEW_USERS, CREATE_USERS, DELETE_USERS,
	VIEW_ROLES, CREATE_ROLES, MODIFY_ROLES, DELETE_ROLES, MODIFY_USER_ROLES,
	//global authorities
	CREATE_TENANTS;
	
	public static final MultiValueMap<Authority, Authority> AUTHORITY_TO_REQUIRED_AUTH = CollectionUtils.toMultiValueMap(Map.ofEntries(
			Map.entry(CREATE_USERS, List.of(VIEW_USERS)),
			Map.entry(DELETE_USERS, List.of(VIEW_USERS)),
			Map.entry(CREATE_ROLES, List.of(VIEW_ROLES)),
			Map.entry(MODIFY_ROLES, List.of(VIEW_ROLES)),
			Map.entry(DELETE_ROLES, List.of(VIEW_ROLES)),
			Map.entry(MODIFY_USER_ROLES, List.of(VIEW_ROLES, VIEW_USERS))));
	
	public static final Set<Authority> ALL_TENANT_AUTHORITIES = Set.of(
			MODIFY_TENANT,
			VIEW_USERS, CREATE_USERS, DELETE_USERS,
			VIEW_ROLES, CREATE_ROLES, MODIFY_ROLES, DELETE_ROLES, MODIFY_USER_ROLES);
	
	public static final Set<Authority> ALL_GLOBAL_AUTHORITIES = Set.of(
			CREATE_TENANTS);
}
