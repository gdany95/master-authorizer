package ro.linic.cloud.master.authorizer.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.common.I18n;
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;
import ro.linic.util.commons.NumberUtils;

@RestController
@RequestMapping("/tenant")
public class TenantController {
	@Autowired private I18n i18n;
	@Autowired private MultiUserRepository userRepository;
	@Autowired private RoleRepository roleRepo;
	@Autowired private TenantRepository tenantRepo;
	
	@PostMapping
	@Secured("CREATE_TENANTS")
	@Transactional
	public Tenant createTenant(@AuthenticationPrincipal final AuthenticatedPrincipal principal, @RequestBody final String name) {
		if (tenantRepo.existsByName(name))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.TenantExists, name));
		
		Tenant tenant = new Tenant();
		tenant.setName(name);
		tenant = tenantRepo.save(tenant);
		
		// default roles
		Role adminRole = new Role();
		adminRole.setName(Role.SUPERADMIN);
		adminRole.setSystem(true);
		adminRole.setTenant(tenant);
		adminRole.setAuthorities(Authority.ALL_TENANT_AUTHORITIES);
		adminRole = roleRepo.save(adminRole);
		
		final Optional<MultiUser> userToChange = findUser(principal);
		userToChange.get().getRoles().add(adminRole);
		
		return tenant;
	}
	
	private Optional<MultiUser> findUser(final AuthenticatedPrincipal principal) {
		return userRepository.findById(NumberUtils.parseToInt(principal.getName()))
        		.or(() -> userRepository.findByPrincipal(principal.getName()));
	}
	
	@PutMapping
	@Secured("MODIFY_TENANT")
	@Transactional
	public Tenant changeName(@RequestHeader("X-TenantID") final int tenantId, @RequestBody final String name) {
		if (tenantRepo.existsByName(name))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.TenantExists, name));
		if (!tenantRepo.existsById(tenantId))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.TenantMissing, tenantId));
		
		final Tenant tenant = tenantRepo.findById(tenantId).get();
		tenant.setName(name);
		return tenant;
	}
}
