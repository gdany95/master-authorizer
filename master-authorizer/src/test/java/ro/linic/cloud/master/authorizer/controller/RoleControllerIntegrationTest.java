package ro.linic.cloud.master.authorizer.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static ro.linic.util.commons.PresentationUtils.LIST_SEPARATOR;
import static ro.linic.util.commons.PresentationUtils.NEWLINE;

import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOAuth2Login;
import com.fasterxml.jackson.databind.ObjectMapper;

import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.TestData;
import ro.linic.cloud.master.authorizer.common.I18n;
import ro.linic.cloud.master.authorizer.dto.RoleUpdateDTO;
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ContextConfiguration(initializers = {RoleControllerIntegrationTest.Initializer.class})
@Testcontainers
@Transactional
public class RoleControllerIntegrationTest {
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
	
	@BeforeEach
	public void init() {
		TestData.init(tenantRepo, roleRepo, userRepo);
	}
	
	@Test
	public void givenUnauthenticated_whenCallApis_thenForbidden() throws Exception {
    	mockMvc.perform(post("/role"))
            .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(put("/role"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(delete("/role/1"))
        .andExpect(status().is3xxRedirection());
    }
	
	@Test
	@WithAnonymousUser
	public void givenAnonymous_whenCallApis_thenForbidden() throws Exception {
    	mockMvc.perform(post("/role"))
            .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(put("/role"))
        .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(delete("/role/1"))
        .andExpect(status().is3xxRedirection());
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenTenantMissing_whenCreateRole_thenThrowException() throws Exception {
		final Role role = new Role();
		role.setName("Rolename");
		
    	mockMvc.perform(post("/role").header("X-TenantID", 1)
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.TenantMissing, 1)));
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenNameEmpty_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Role role = new Role();
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameMandatory)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenSystemRole_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Role role = new Role();
		role.setName("Rolename");
		role.setSystem(true);
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_SystemRoleErr)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenMissingRequiredAuths_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Set<Authority> sourceAuths = Authority.AUTHORITY_TO_REQUIRED_AUTH.keySet();
		final String requiredAuths = sourceAuths.stream()
				.flatMap(invalidAuth -> Authority.AUTHORITY_TO_REQUIRED_AUTH.get(invalidAuth).stream())
				.distinct()
				.map(Authority::toString)
				.sorted()
				.map(i18n::msg)
				.collect(Collectors.joining(LIST_SEPARATOR));
		
		final Role role = new Role();
		role.setName("Rolename");
		role.setAuthorities(sourceAuths);
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_InvalidAuthorities, NEWLINE,
					sourceAuths.stream().map(Authority::toString).sorted().map(i18n::msg).collect(Collectors.joining(LIST_SEPARATOR)),
					requiredAuths)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenHasGlobalAuths_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Role role = new Role();
		role.setName("Rolename");
		role.setAuthorities(Set.of(Authority.CREATE_TENANTS));
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_NotTenantAuth,
					Role.authoritiesToText(role.getAuthorities(), LIST_SEPARATOR, i18n))));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenIsSuperadmin_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Role role = new Role();
		role.setName(Role.SUPERADMIN);
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameReserved, Role.SUPERADMIN)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenIsSysadmin_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Role role = new Role();
		role.setName(Role.SYSADMIN);
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(role)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameReserved, Role.SYSADMIN)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
	public void givenRoleExists_whenCreateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
    	mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(TestData.defaultRole)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_RoleExists)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_ROLES")
    public void givenValidRole_whenCreateRole_thenSaveRole() throws Exception {
		TestData.saveData();
		
		final Role newRole = new Role();
		newRole.setName("New role");
		newRole.setTenant(TestData.defaultTenant);
		newRole.setAuthorities(Authority.ALL_TENANT_AUTHORITIES);
		
    	final MvcResult result = mockMvc.perform(post("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(newRole)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();
    	final Role roleResult = objectMapper.readValue(result.getResponse().getContentAsString(), Role.class);
    	
    	assertThat(roleRepo.existsById(roleResult.getId())).isTrue();
    	assertThat(roleResult.getName()).isEqualTo(newRole.getName());
    	assertThat(roleResult.getTenant()).isEqualTo(TestData.defaultTenant);
    	assertThat(roleResult.getAuthorities()).containsExactlyInAnyOrderElementsOf(newRole.getAuthorities());
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenRoleMissing_whenUpdateRole_thenThrowException() throws Exception {
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(1);
		roleDto.setName("Rolename");
		
    	mockMvc.perform(put("/role").header("X-TenantID", 1)
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleMissing, roleDto.getId())));
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenNameEmpty_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameMandatory)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenSystemRole_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.superadminRole.getId());
		roleDto.setName("Rolename");
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_SystemRoleErr)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenMissingRequiredAuths_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final Set<Authority> sourceAuths = Authority.AUTHORITY_TO_REQUIRED_AUTH.keySet();
		final String requiredAuths = sourceAuths.stream()
				.flatMap(invalidAuth -> Authority.AUTHORITY_TO_REQUIRED_AUTH.get(invalidAuth).stream())
				.distinct()
				.map(Authority::toString)
				.sorted()
				.map(i18n::msg)
				.collect(Collectors.joining(LIST_SEPARATOR));
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName("Rolename");
		roleDto.setAuthorities(sourceAuths);
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_InvalidAuthorities, NEWLINE,
					sourceAuths.stream().map(Authority::toString).sorted().map(i18n::msg).collect(Collectors.joining(LIST_SEPARATOR)),
					requiredAuths)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenHasGlobalAuths_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName("Rolename");
		roleDto.setAuthorities(Set.of(Authority.CREATE_TENANTS));
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_NotTenantAuth,
					Role.authoritiesToText(roleDto.getAuthorities(), LIST_SEPARATOR, i18n))));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenIsSuperadmin_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName(Role.SUPERADMIN);
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameReserved, Role.SUPERADMIN)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenIsSysadmin_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName(Role.SYSADMIN);
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.NameReserved, Role.SYSADMIN)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenTenantsMismatch_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName("Some role");
		
    	mockMvc.perform(put("/role").header("X-TenantID", tenant2.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_RoleTenantMismatch, TestData.defaultRole.getTenantId(), tenant2.getId())));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenRoleExists_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		Role role2 = new Role();
		role2.setName("Rolename exists");
		role2.setTenant(TestData.defaultTenant);
		role2.setAuthorities(Authority.ALL_TENANT_AUTHORITIES);
		role2 = roleRepo.save(role2);
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName(role2.getName());
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_RoleExists)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
	public void givenIsGlobalRole_whenUpdateRole_thenThrowException() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.globalRole.getId());
		roleDto.setName("New name");
		
    	mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_SystemRoleErr)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_ROLES")
    public void givenValidRole_whenUpdateRole_thenSaveRole() throws Exception {
		TestData.saveData();
		
		final RoleUpdateDTO roleDto = new RoleUpdateDTO();
		roleDto.setId(TestData.defaultRole.getId());
		roleDto.setName("New role name");
		roleDto.setAuthorities(Set.of(Authority.VIEW_USERS));
		
		final MvcResult result = mockMvc.perform(put("/role").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(objectMapper.writeValueAsString(roleDto)).contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();
    	final Role roleResult = objectMapper.readValue(result.getResponse().getContentAsString(), Role.class);
    	
    	assertThat(roleRepo.existsById(roleResult.getId())).isTrue();
    	assertThat(roleResult.getName()).isEqualTo(roleDto.getName());
    	assertThat(roleResult.getTenant()).isEqualTo(TestData.defaultTenant);
    	assertThat(roleResult.getAuthorities()).containsExactly(Authority.VIEW_USERS);
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_ROLES")
	public void givenTenantsMismatch_whenDeleteRole_thenThrowException() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
    	mockMvc.perform(delete("/role/"+TestData.defaultRole.getId()).header("X-TenantID", tenant2.getId()))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_RoleTenantMismatch, TestData.defaultRole.getTenantId(), tenant2.getId())));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_ROLES")
	public void givenSystemRole_whenDeleteRole_thenThrowException() throws Exception {
		TestData.saveData();
		
    	mockMvc.perform(delete("/role/"+TestData.superadminRole.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.RoleController_SystemRoleErr)));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_ROLES")
	public void givenRoleMissing_whenDeleteRole_thenDoNothing() throws Exception {
    	mockMvc.perform(delete("/role/"+1).header("X-TenantID", 1))
            .andExpect(status().isOk());
    }
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_ROLES")
    public void givenValid_whenDeleteRole_thenReturnOk() throws Exception {
		TestData.saveData();
		
		mockMvc.perform(delete("/role/"+TestData.defaultRole.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
            .andExpect(status().isOk());
    	assertThat(roleRepo.existsById(TestData.defaultRole.getId())).isFalse();
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "DELETE_ROLES")
    public void givenUsersAssigned_whenDeleteRole_thenAlsoDeleteConnectionsToUser() throws Exception {
		TestData.saveData();
		
		mockMvc.perform(delete("/role/"+TestData.defaultRole.getId()).header("X-TenantID", TestData.defaultTenant.getId()))
            .andExpect(status().isOk());
    	assertThat(roleRepo.existsById(TestData.defaultRole.getId())).isFalse();
    	assertThat(userRepo.existsById(TestData.defaultUser.getId())).isTrue();
    	
    	TestData.deleteAllData();
    }
}
