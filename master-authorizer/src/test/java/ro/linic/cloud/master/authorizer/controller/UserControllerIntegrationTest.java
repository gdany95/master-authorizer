package ro.linic.cloud.master.authorizer.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOAuth2Login;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.TestData;
import ro.linic.cloud.master.authorizer.common.I18n;
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.InviteToken;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.InviteTokenRepository;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ContextConfiguration(initializers = {UserControllerIntegrationTest.Initializer.class})
@Testcontainers
@Transactional
public class UserControllerIntegrationTest {
	@Container
	private static PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres").withTag("10"));
	
	static class Initializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
		@Override
		public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
			TestPropertyValues
					.of("spring.datasource.url=" + postgresContainer.getJdbcUrl(),
							"spring.datasource.username=" + postgresContainer.getUsername(),
							"spring.datasource.password=" + postgresContainer.getPassword())
					.applyTo(configurableApplicationContext.getEnvironment());
		}
	}
	
	@Autowired private MockMvc mockMvc;
	@Autowired private I18n i18n;
	@Autowired private ObjectMapper objectMapper;
	@Autowired private TenantRepository tenantRepo;
	@Autowired private RoleRepository roleRepo;
	@Autowired private MultiUserRepository userRepo;
	@Autowired private InviteTokenRepository tokenRepo;
	
	@BeforeEach
	public void init() {
		TestData.init(tenantRepo, roleRepo, userRepo);
	}
	
	@Test
	public void givenUnauthenticated_whenCallApis_thenForbidden() throws Exception {
		mockMvc.perform(get("/user"))
        .andExpect(status().is3xxRedirection());
		
    	mockMvc.perform(get("/user/authorities"))
            .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(delete("/user"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(delete("/user/1"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(put("/user/1/roles"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(put("/user"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(post("/user"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(get("/user/accept/token"))
        .andExpect(status().is3xxRedirection());
    	mockMvc.perform(post("/user/accept/token"))
        .andExpect(status().is3xxRedirection());
    }
	
	@Test
	@WithOAuth2Login
	public void givenUserMissing_whenAuthorities_thenReturnEmptyAuths() throws Exception {
		final MvcResult result = mockMvc.perform(get("/user/authorities").header("X-TenantID", 1))
				.andExpect(status().isOk())
				.andReturn();
		final Set<Authority> authsResult = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<Set<Authority>>(){});
		assertThat(authsResult).isEmpty();
    }
	
	@Test
	@WithOAuth2Login
	public void givenDefaultUser_whenAuthorities_thenReturnDefaultAuths() throws Exception {
		TestData.saveData();

		final MvcResult result = mockMvc.perform(get("/user/authorities").header("X-TenantID", TestData.defaultTenant.getId()))
				.andExpect(status().isOk())
				.andReturn();
		final Set<Authority> authsResult = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<Set<Authority>>(){});
		assertThat(authsResult).containsExactlyInAnyOrderElementsOf(Authority.ALL_TENANT_AUTHORITIES);

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenMultipleRolesForUser_whenAuthorities_thenReturnAuthsForTenant() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
		Role tenant2Role = new Role();
		tenant2Role.setName("Default role");
		tenant2Role.setTenant(tenant2);
		tenant2Role.setAuthorities(Set.of(Authority.VIEW_ROLES));
		tenant2Role = roleRepo.save(tenant2Role);
		
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(TestData.defaultRole);
		TestData.defaultUser.getRoles().add(tenant2Role);

		final MvcResult result = mockMvc.perform(get("/user/authorities").header("X-TenantID", tenant2.getId()))
				.andExpect(status().isOk())
				.andReturn();
		final Set<Authority> authsResult = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<Set<Authority>>(){});
		assertThat(authsResult).containsExactly(Authority.VIEW_ROLES);

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenHasAlsoGlobalRole_whenAuthorities_thenConcatGlobalAuths() throws Exception {
		TestData.saveData();
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(TestData.defaultRole);
		TestData.defaultUser.getRoles().add(TestData.globalRole);

		final MvcResult result = mockMvc.perform(get("/user/authorities").header("X-TenantID", TestData.defaultTenant.getId()))
				.andExpect(status().isOk())
				.andReturn();
		final Set<Authority> authsResult = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<Set<Authority>>(){});
		assertThat(authsResult).containsExactlyInAnyOrderElementsOf(Stream.concat(Authority.ALL_TENANT_AUTHORITIES.stream(),
				Authority.ALL_GLOBAL_AUTHORITIES.stream()).collect(Collectors.toSet()));

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenHasGlobalRole_whenAuthorities_thenReturnGlobalAuths() throws Exception {
		TestData.saveData();
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(TestData.globalRole);

		final MvcResult result = mockMvc.perform(get("/user/authorities").header("X-TenantID", TestData.defaultTenant.getId()))
				.andExpect(status().isOk())
				.andReturn();
		final Set<Authority> authsResult = objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<Set<Authority>>(){});
		assertThat(authsResult).containsExactlyElementsOf(Authority.ALL_GLOBAL_AUTHORITIES);

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenDefaultUser_whenDeleteMyself_thenDeleteUser() throws Exception {
		TestData.saveData();

		mockMvc.perform(delete("/user"))
				.andExpect(status().isOk());
		assertThat(userRepo.findById(TestData.defaultUser.getId())).isEmpty();
		assertThat(userRepo.findAll()).isEmpty();

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_USERS")
	public void givenUserMissing_whenRemoveFromTenant_thenDoNothing() throws Exception {
		mockMvc.perform(delete("/user/-1").header("X-TenantID", 1))
				.andExpect(status().isOk());
		assertThat(userRepo.findById(1)).isEmpty();
		assertThat(userRepo.findAll()).isEmpty();
	}
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_USERS")
	public void givenAdminUser_whenRemoveFromTenant_thenThrowException() throws Exception {
		TestData.saveData();
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(TestData.superadminRole);

		mockMvc.perform(delete("/user/"+TestData.defaultUser.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
			.andExpect(status().isNotAcceptable())
			.andExpect(status().reason(i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SUPERADMIN)));

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_USERS")
	public void givenSysadminUser_whenRemoveFromTenant_thenThrowException() throws Exception {
		TestData.saveData();
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(TestData.sysadminRole);

		mockMvc.perform(delete("/user/"+TestData.defaultUser.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
			.andExpect(status().isNotAcceptable())
			.andExpect(status().reason(i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SYSADMIN)));

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_USERS")
	public void givenDefaultUser_whenRemoveFromTenant_thenRemoveTenantRoles() throws Exception {
		TestData.saveData();

		mockMvc.perform(delete("/user/"+TestData.defaultUser.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
				.andExpect(status().isOk());
		final Optional<MultiUser> user = userRepo.findById(TestData.defaultUser.getId());
		assertThat(user).isPresent();
		assertThat(user.get().rolesOfTenant(TestData.defaultTenant.getId())).isEmpty();
		assertThat(user.get().getRoles()).isEmpty();

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_USERS")
	public void givenHasMultipleRoles_whenRemoveFromTenant_thenRemoveTenantRoles() throws Exception {
		TestData.saveData();
		Role defTenantRole1 = new Role();
		defTenantRole1.setName("Tenant 1 Role 1");
		defTenantRole1.setTenant(TestData.defaultTenant);
		defTenantRole1.setAuthorities(Set.of(Authority.VIEW_USERS, Authority.CREATE_USERS));
		defTenantRole1 = roleRepo.save(defTenantRole1);
		
		Role defTenantRole2 = new Role();
		defTenantRole2.setName("Tenant 1 Role 2");
		defTenantRole2.setTenant(TestData.defaultTenant);
		defTenantRole2.setAuthorities(Set.of(Authority.VIEW_USERS));
		defTenantRole2 = roleRepo.save(defTenantRole2);
		
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
		Role tenant2Role = new Role();
		tenant2Role.setName("Tenant 2 Default role");
		tenant2Role.setTenant(tenant2);
		tenant2Role.setAuthorities(Set.of(Authority.VIEW_ROLES));
		tenant2Role = roleRepo.save(tenant2Role);
		
		TestData.defaultUser.setRoles(new HashSet<>());
		TestData.defaultUser.getRoles().add(defTenantRole1);
		TestData.defaultUser.getRoles().add(defTenantRole2);
		TestData.defaultUser.getRoles().add(tenant2Role);
		TestData.defaultUser.getRoles().add(TestData.globalRole);
		
		mockMvc.perform(delete("/user/"+TestData.defaultUser.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
				.andExpect(status().isOk());
		final Optional<MultiUser> user = userRepo.findById(TestData.defaultUser.getId());
		assertThat(user).isPresent();
		assertThat(user.get().rolesOfTenant(TestData.defaultTenant.getId())).isEmpty();
		assertThat(user.get().rolesOfTenant(tenant2.getId())).containsExactly(tenant2Role);
		assertThat(user.get().globalRoles()).containsExactly(TestData.globalRole);
		assertThat(user.get().getRoles()).hasSize(2);
		assertThat(user.get().allAuthorities())
		.containsExactlyInAnyOrderElementsOf(Stream.concat(Authority.ALL_GLOBAL_AUTHORITIES.stream(), tenant2Role.getAuthorities().stream()).collect(Collectors.toSet()));

		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenUserMissing_whenModifyUserRoles_thenDoNothing() throws Exception {
		mockMvc.perform(put("/user/1/roles").header("X-TenantID", 1)
				.content(objectMapper.writeValueAsString(Set.of())).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userRepo.findById(1)).isEmpty();
		assertThat(userRepo.findAll()).isEmpty();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenNewRoleIsSuperadmin_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.superadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_SuperadminRequired, Role.SUPERADMIN)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenNewRoleIsSuperadminPermitted_whenModifyUserRoles_thenChangeRole() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.superadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactly(TestData.superadminRole);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenOldRoleIsSuperadmin_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.superadminRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.defaultRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_SuperadminChangeAnother, Role.SUPERADMIN)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenOldRoleIsSuperadminPermitted_whenModifyUserRoles_thenChangeRole() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.superadminRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.defaultRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactly(TestData.defaultRole);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenNewRoleIsSysadmin_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.sysadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_RoleReserved, Role.SYSADMIN)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenOldRoleIsSysadmin_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.sysadminRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.defaultRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_ChangeNotAllowed, Role.SYSADMIN)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenNewRoleFromAnotherTenant_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
		Role roleTenant2 = new Role();
		roleTenant2.setName("Default role tenant 2");
		roleTenant2.setTenant(tenant2);
		roleTenant2.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		roleTenant2 = roleRepo.save(roleTenant2);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(roleTenant2.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.TenantMismatch)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenNewRoleIsGlobal_whenModifyUserRoles_thenThrowException() throws Exception {
		TestData.saveData();
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.globalRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_GlobalRoleNotAllowed)));
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenValidChange_whenModifyUserRoles_thenChangeRole() throws Exception {
		TestData.saveData();
		
		Role newRole = new Role();
		newRole.setName("New role");
		newRole.setTenant(TestData.defaultTenant);
		newRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		newRole = roleRepo.save(newRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactly(newRole);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenHasOldGlobal_whenModifyUserRoles_thenKeepGlobal() throws Exception {
		TestData.saveData();
		
		Role newRole = new Role();
		newRole.setName("New role");
		newRole.setTenant(TestData.defaultTenant);
		newRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		newRole = roleRepo.save(newRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange.getRoles().add(TestData.globalRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactlyInAnyOrder(TestData.globalRole, newRole);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenHasMultipleRoles_whenModifyUserRoles_thenRemoveOldRoles() throws Exception {
		TestData.saveData();
		
		Role oldRole1 = new Role();
		oldRole1.setName("Old role 1");
		oldRole1.setTenant(TestData.defaultTenant);
		oldRole1.getAuthorities().add(Authority.VIEW_ROLES);
		oldRole1 = roleRepo.save(oldRole1);
		
		Role oldRole2 = new Role();
		oldRole2.setName("Old role 2");
		oldRole2.setTenant(TestData.defaultTenant);
		oldRole2.getAuthorities().add(Authority.VIEW_USERS);
		oldRole2 = roleRepo.save(oldRole2);
		
		Role newRole = new Role();
		newRole.setName("New role");
		newRole.setTenant(TestData.defaultTenant);
		newRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		newRole = roleRepo.save(newRole);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange.getRoles().add(oldRole1);
		userToChange.getRoles().add(oldRole2);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactlyInAnyOrder(newRole);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenMultipleNewRoles_whenModifyUserRoles_thenAddAllNewRoles() throws Exception {
		TestData.saveData();
		
		Role newRole1 = new Role();
		newRole1.setName("New role 1");
		newRole1.setTenant(TestData.defaultTenant);
		newRole1.getAuthorities().add(Authority.VIEW_ROLES);
		newRole1 = roleRepo.save(newRole1);
		
		Role newRole2 = new Role();
		newRole2.setName("New role 2");
		newRole2.setTenant(TestData.defaultTenant);
		newRole2.getAuthorities().add(Authority.VIEW_USERS);
		newRole2 = roleRepo.save(newRole2);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().add(TestData.defaultRole);
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole1.getId(), newRole2.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactlyInAnyOrder(newRole1, newRole2);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_USER_ROLES")
	public void givenHasRolesToMultipleTenants_whenModifyUserRoles_thenKeepOtherTenantsRoles() throws Exception {
		TestData.saveData();
		
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		Tenant tenant3 = new Tenant();
		tenant3.setName("Tenant 3");
		tenant3 = tenantRepo.save(tenant3);
		
		Role oldRoleTenant2 = new Role();
		oldRoleTenant2.setName("oldRoleTenant2");
		oldRoleTenant2.setTenant(tenant2);
		oldRoleTenant2.getAuthorities().addAll(Authority.ALL_TENANT_AUTHORITIES);
		oldRoleTenant2 = roleRepo.save(oldRoleTenant2);
		Role oldRoleTenant3 = new Role();
		oldRoleTenant3.setName("oldRoleTenant3");
		oldRoleTenant3.setTenant(tenant3);
		oldRoleTenant3.getAuthorities().add(Authority.VIEW_ROLES);
		oldRoleTenant3 = roleRepo.save(oldRoleTenant3);
		Role oldRoleSuperadminTenant3 = new Role();
		oldRoleSuperadminTenant3.setName(Role.SUPERADMIN);
		oldRoleSuperadminTenant3.setSystem(true);
		oldRoleSuperadminTenant3.setTenant(tenant3);
		oldRoleSuperadminTenant3.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		oldRoleSuperadminTenant3 = roleRepo.save(oldRoleSuperadminTenant3);
		
		Role newRole1 = new Role();
		newRole1.setName("New role 1");
		newRole1.setTenant(TestData.defaultTenant);
		newRole1.getAuthorities().add(Authority.VIEW_ROLES);
		newRole1 = roleRepo.save(newRole1);
		Role newRole2 = new Role();
		newRole2.setName("New role 2");
		newRole2.setTenant(TestData.defaultTenant);
		newRole2.getAuthorities().add(Authority.VIEW_USERS);
		newRole2 = roleRepo.save(newRole2);
		
		MultiUser userToChange = new MultiUser();
		userToChange.setPrincipals(new HashSet<>(Set.of("userToCh")));
		userToChange.getRoles().addAll(Set.of(TestData.defaultRole, TestData.globalRole, oldRoleTenant2, oldRoleTenant3, oldRoleSuperadminTenant3));
		userToChange = userRepo.save(userToChange);

		mockMvc.perform(put("/user/"+userToChange.getId()+"/roles").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole1.getId(), newRole2.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk());
		assertThat(userToChange.getRoles()).containsExactlyInAnyOrder(TestData.globalRole, newRole1, newRole2, oldRoleTenant2,
				oldRoleTenant3, oldRoleSuperadminTenant3);
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenValidChange_whenChangeName_thenChange() throws Exception {
		TestData.saveData();
		
		mockMvc.perform(put("/user").content("my brand new name"))
				.andExpect(status().isOk());
		assertThat(TestData.defaultUser.getDisplayName()).isEqualTo("my brand new name");
		
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenTenantMissing_whenInviteToTenant_thenThrowException() throws Exception {
		mockMvc.perform(post("/user").header("X-TenantID", 1)
				.content(objectMapper.writeValueAsString(Set.of())).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isPreconditionFailed())
				.andExpect(status().reason(i18n.msg(Messages.TenantMissing, 1)));
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenNewRoleIsSuperadmin_whenInviteToTenant_thenThrowException() throws Exception {
		TestData.saveData();

		mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.superadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_SuperadminRequired, Role.SUPERADMIN)));
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenNewRoleIsSuperadminPermitted_whenInviteToTenant_thenCreateInvite() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		final MvcResult result = mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.superadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andReturn();
		final InviteToken token = tokenRepo.findById(result.getResponse().getContentAsString()).get();
		assertThat(token.getTenant()).isEqualTo(TestData.defaultTenant);
		assertThat(token.getRoles()).containsExactly(TestData.superadminRole.getId());
		assertThat(token.getToken()).hasSizeGreaterThan(16);
		assertThat(token.isExpired()).isFalse();
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenNewRoleIsSysadmin_whenInviteToTenant_thenThrowException() throws Exception {
		TestData.saveData();
		TestData.defaultUser.getRoles().add(TestData.superadminRole);
		
		mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.sysadminRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_RoleReserved, Role.SYSADMIN)));
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenNewRoleFromAnotherTenant_whenInviteToTenant_thenThrowException() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
		Role roleTenant2 = new Role();
		roleTenant2.setName("Default role tenant 2");
		roleTenant2.setTenant(tenant2);
		roleTenant2.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		roleTenant2 = roleRepo.save(roleTenant2);
		
		mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(roleTenant2.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.TenantMismatch)));
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenNewRoleIsGlobal_whenInviteToTenant_thenThrowException() throws Exception {
		TestData.saveData();

		mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(TestData.globalRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(status().reason(i18n.msg(Messages.UserController_GlobalRoleNotAllowed)));
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenValidChange_whenInviteToTenant_thenCreateInvite() throws Exception {
		TestData.saveData();
		
		Role newRole = new Role();
		newRole.setName("New role");
		newRole.setTenant(TestData.defaultTenant);
		newRole.setAuthorities(new HashSet<>(Authority.ALL_TENANT_AUTHORITIES));
		newRole = roleRepo.save(newRole);
		
		final MvcResult result = mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andReturn();
		final InviteToken token = tokenRepo.findById(result.getResponse().getContentAsString()).get();
		assertThat(token.getTenant()).isEqualTo(TestData.defaultTenant);
		assertThat(token.getRoles()).containsExactly(newRole.getId());
		assertThat(token.getToken()).hasSizeGreaterThan(16);
		assertThat(token.isExpired()).isFalse();
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_USERS")
	public void givenMultipleNewRoles_whenInviteToTenant_thenAddAllNewRoles() throws Exception {
		TestData.saveData();
		
		Role newRole1 = new Role();
		newRole1.setName("New role 1");
		newRole1.setTenant(TestData.defaultTenant);
		newRole1.getAuthorities().add(Authority.VIEW_ROLES);
		newRole1 = roleRepo.save(newRole1);
		
		Role newRole2 = new Role();
		newRole2.setName("New role 2");
		newRole2.setTenant(TestData.defaultTenant);
		newRole2.getAuthorities().add(Authority.VIEW_USERS);
		newRole2 = roleRepo.save(newRole2);
		
		final MvcResult result = mockMvc.perform(post("/user").header("X-TenantID", TestData.defaultTenant.getId())
				.content(objectMapper.writeValueAsString(Set.of(newRole1.getId(), newRole2.getId()))).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andReturn();
		final InviteToken token = tokenRepo.findById(result.getResponse().getContentAsString()).get();
		assertThat(token.getTenant()).isEqualTo(TestData.defaultTenant);
		assertThat(token.getRoles()).containsExactlyInAnyOrder(newRole1.getId(), newRole2.getId());
		assertThat(token.getToken()).hasSizeGreaterThan(16);
		assertThat(token.isExpired()).isFalse();
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenTokenMissing_whenAcceptInvite_thenThrowException() throws Exception {
		mockMvc.perform(post("/user/accept/token"))
				.andExpect(status().isBadRequest())
				.andExpect(status().reason(i18n.msg(Messages.InviteTokenInvalid)));
	}
	
	@Test
	@WithOAuth2Login
	public void givenTokenExpired_whenAcceptInvite_thenThrowException() throws Exception {
		TestData.saveData();
		InviteToken token = new InviteToken();
		token.setToken("token");
		token.setTenant(TestData.defaultTenant);
		token.setExpiryDate(Instant.now().minusSeconds(10));
		token = tokenRepo.save(token);
		
		mockMvc.perform(post("/user/accept/"+token.getToken()))
		.andExpect(status().isBadRequest())
		.andExpect(status().reason(i18n.msg(Messages.InviteTokenInvalid)));
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenRoleMissing_whenAcceptInvite_thenDoNothing() throws Exception {
		TestData.saveData();
		InviteToken token = new InviteToken();
		token.setToken("token");
		token.setTenant(TestData.defaultTenant);
		token.getRoles().add(-1L);
		token = tokenRepo.save(token);
		
		mockMvc.perform(post("/user/accept/"+token.getToken()))
		.andExpect(status().isOk());
		
		assertThat(TestData.defaultUser.getRoles()).containsExactly(TestData.defaultRole);
		assertThat(tokenRepo.findById(token.getToken())).isEmpty();
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
	
	@Test
	@WithOAuth2Login
	public void givenValidToken_whenAcceptInvite_thenAddRolesAndDeleteToken() throws Exception {
		TestData.saveData();
		InviteToken token = new InviteToken();
		token.setToken("token");
		token.setTenant(TestData.defaultTenant);
		token.getRoles().add(TestData.superadminRole.getId());
		token = tokenRepo.save(token);
		
		mockMvc.perform(post("/user/accept/"+token.getToken()))
		.andExpect(status().isOk());
		
		assertThat(TestData.defaultUser.getRoles()).containsExactlyInAnyOrder(TestData.defaultRole, TestData.superadminRole);
		assertThat(tokenRepo.findById(token.getToken())).isEmpty();
		
		tokenRepo.deleteAll();
		TestData.deleteAllData();
	}
}
