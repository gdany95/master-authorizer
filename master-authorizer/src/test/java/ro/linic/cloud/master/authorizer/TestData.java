package ro.linic.cloud.master.authorizer;

import java.util.HashSet;
import java.util.Set;

import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;

public class TestData {
	private static TenantRepository tenantRepo;
	private static RoleRepository roleRepo;
	private static MultiUserRepository userRepo;
	
	public static Tenant defaultTenant;
	public static Role defaultRole;
	public static Role superadminRole;
	public static Role sysadminRole;
	public static Role globalRole;
	public static MultiUser defaultUser;
	
	public static void init(final TenantRepository tenantRepo, final RoleRepository roleRepo, final MultiUserRepository userRepo) {
		TestData.tenantRepo = tenantRepo;
		TestData.roleRepo = roleRepo;
		TestData.userRepo = userRepo;
	}
	
	public static void saveData() {
		defaultTenant = new Tenant();
		defaultTenant.setName("Tenant 1");
		defaultTenant = tenantRepo.save(defaultTenant);
		
		defaultRole = new Role();
		defaultRole.setName("Default role");
		defaultRole.setTenant(defaultTenant);
		defaultRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		defaultRole = roleRepo.save(defaultRole);
		
		superadminRole = new Role();
		superadminRole.setName(Role.SUPERADMIN);
		superadminRole.setSystem(true);
		superadminRole.setTenant(defaultTenant);
		superadminRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		superadminRole = roleRepo.save(superadminRole);
		
		sysadminRole = new Role();
		sysadminRole.setName(Role.SYSADMIN);
		sysadminRole.setSystem(true);
		sysadminRole.setTenant(defaultTenant);
		sysadminRole.setAuthorities(new HashSet<>(Authority.ALL_GLOBAL_AUTHORITIES));
		sysadminRole = roleRepo.save(sysadminRole);
		
		globalRole = new Role();
		globalRole.setName("Global role");
		globalRole.setAuthorities(new HashSet<>(Authority.ALL_GLOBAL_AUTHORITIES));
		globalRole = roleRepo.save(globalRole);
		
		defaultUser = new MultiUser();
		defaultUser.setDisplayName("Default User");
		defaultUser.setPrincipals(new HashSet<>(Set.of("user")));
		defaultUser.setRoles(new HashSet<>(Set.of(defaultRole)));
		defaultUser = userRepo.save(defaultUser);
	}
	
	public static void deleteAllData() {
		userRepo.deleteAll();
		roleRepo.deleteAll();
		tenantRepo.deleteAll();
	}
}
