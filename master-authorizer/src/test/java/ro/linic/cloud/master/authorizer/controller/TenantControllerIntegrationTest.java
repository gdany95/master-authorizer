package ro.linic.cloud.master.authorizer.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
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
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ContextConfiguration(initializers = {TenantControllerIntegrationTest.Initializer.class})
@Testcontainers
@Transactional
public class TenantControllerIntegrationTest {
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
    	mockMvc.perform(post("/tenant"))
            .andExpect(status().is3xxRedirection());
    	
    	mockMvc.perform(put("/tenant"))
        .andExpect(status().is3xxRedirection());
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_TENANTS")
	public void givenTenantExists_whenCreateTenant_thenThrowException() throws Exception {
		TestData.saveData();
		
    	mockMvc.perform(post("/tenant")
    			.content(TestData.defaultTenant.getName()))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.TenantExists, TestData.defaultTenant.getName())));
    	
		TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "CREATE_TENANTS")
	public void givenNewTenant_whenCreateTenant_thenAlsoCreateDefaultRoles() throws Exception {
		MultiUser defaultUser = new MultiUser();
		defaultUser.setDisplayName("Default User");
		defaultUser.setPrincipals(Set.of("user"));
		defaultUser = userRepo.save(defaultUser);
		
    	final MvcResult result = mockMvc.perform(post("/tenant")
    			.content("Some tenant"))
            .andExpect(status().isOk())
            .andReturn();
    	final Tenant tenantResult = objectMapper.readValue(result.getResponse().getContentAsString(), Tenant.class);
    	
    	assertThat(tenantRepo.existsById(tenantResult.getId())).isTrue();
    	assertThat(tenantResult.getName()).isEqualTo("Some tenant");
    	assertThat(roleRepo.findAll()).hasSize(1);
    	final Role role = roleRepo.findAll().get(0);
    	assertThat(role.getName()).isEqualTo(Role.SUPERADMIN);
    	assertThat(role.getTenant()).isEqualTo(tenantResult);
    	assertThat(role.isSystem()).isTrue();
    	assertThat(role.getAuthorities()).containsExactlyElementsOf(Authority.ALL_TENANT_AUTHORITIES);
    	assertThat(userRepo.findAll()).hasSize(1);
    	defaultUser = userRepo.findAll().get(0);
    	assertThat(defaultUser.getRoles()).hasSize(1);
    	assertThat(defaultUser.getRoles().iterator().next()).isEqualTo(role);
    	
    	userRepo.deleteAll();
		roleRepo.deleteAll();
		tenantRepo.deleteAll();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_TENANT")
	public void givenTenantExists_whenChangeTenant_thenThrowException() throws Exception {
		TestData.saveData();
		Tenant tenant2 = new Tenant();
		tenant2.setName("Tenant 2");
		tenant2 = tenantRepo.save(tenant2);
		
    	mockMvc.perform(put("/tenant").header("X-TenantID", TestData.defaultTenant.getId())
    			.content(tenant2.getName()))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.TenantExists, tenant2.getName())));
    	
    	TestData.deleteAllData();
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_TENANT")
	public void givenTenantMissing_whenChangeTenant_thenThrowException() throws Exception {
    	mockMvc.perform(put("/tenant").header("X-TenantID", 1)
    			.content("Some other name"))
            .andExpect(status().isBadRequest())
            .andExpect(status().reason(i18n.msg(Messages.TenantMissing, 1)));
    }
	
	@Test
	@WithOAuth2Login(authorities = "MODIFY_TENANT")
	public void givenValid_whenChangeTenant_thenModifyName() throws Exception {
		TestData.saveData();
		
    	final MvcResult result = mockMvc.perform(put("/tenant").header("X-TenantID", TestData.defaultTenant.getId())
    			.content("Changed Name"))
            .andExpect(status().isOk())
            .andReturn();
    	final Tenant tenantResult = objectMapper.readValue(result.getResponse().getContentAsString(), Tenant.class);
    	assertThat(tenantResult.getName()).isEqualTo("Changed Name");
    	
    	TestData.deleteAllData();
    }
}
