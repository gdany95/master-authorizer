package ro.linic.cloud.master.authorizer.controller;

import static ro.linic.util.commons.PresentationUtils.LIST_SEPARATOR;
import static ro.linic.util.commons.PresentationUtils.NEWLINE;
import static ro.linic.util.commons.StringUtils.globalIsMatch;
import static ro.linic.util.commons.StringUtils.isEmpty;
import static ro.linic.util.commons.StringUtils.processForStoring;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.common.I18n;
import ro.linic.cloud.master.authorizer.dto.RoleUpdateDTO;
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;
import ro.linic.util.commons.StringUtils.TextFilterMethod;

@RestController
@RequestMapping("/role")
public class RoleController {
	@Autowired private I18n i18n;
	@Autowired private MultiUserRepository userRepo;
	@Autowired private RoleRepository roleRepo;
	@Autowired private TenantRepository tenantRepo;
	
	@PostMapping
	@Secured("CREATE_ROLES")
	@Transactional
	public Role createRole(@RequestHeader("X-TenantID") final int tenantId, @RequestBody final Role role) {
		if (!tenantRepo.existsById(tenantId))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.TenantMissing, tenantId));
		
		role.setName(processForStoring(role.getName()));
		role.setTenant(tenantRepo.findById(tenantId).get());
		validateRole(role);
		
		if (rolenameIsUsed(role))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_RoleExists));
		
		return roleRepo.save(role);
	}
	
	private void validateRole(final Role role) {
		// required name
		if (isEmpty(role.getName()))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.NameMandatory));
		
		// cannot be system role
		if (role.isSystem())
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_SystemRoleErr));
		
		final Set<Authority> authorities = role.getAuthorities();
		final Set<Authority> invalidAuthorities = authorities.stream()
			.filter(auth -> !authorities.containsAll(Authority.AUTHORITY_TO_REQUIRED_AUTH.getOrDefault(auth, List.of())))
			.collect(Collectors.toUnmodifiableSet());
		
		// check that all required authorities are added for the selected authorities
		if (!invalidAuthorities.isEmpty())
		{
			final String sourceAuths = invalidAuthorities.stream()
					.map(Authority::toString)
					.sorted()
					.map(i18n::msg)
					.collect(Collectors.joining(LIST_SEPARATOR));
			final String requiredAuths = invalidAuthorities.stream()
					.flatMap(invalidAuth -> Authority.AUTHORITY_TO_REQUIRED_AUTH.get(invalidAuth).stream())
					.distinct()
					.map(Authority::toString)
					.sorted()
					.map(i18n::msg)
					.collect(Collectors.joining(LIST_SEPARATOR));
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_InvalidAuthorities, NEWLINE,
					sourceAuths, requiredAuths));
		}
		
		// check that the role contains only user visible authorities
		if (authorities.stream().anyMatch(auth -> !Authority.ALL_TENANT_AUTHORITIES.contains(auth)))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_NotTenantAuth,
					Role.authoritiesToText(role.getAuthorities(), LIST_SEPARATOR, i18n)));
		
		// cannot be Superadmin role
		if (globalIsMatch(role.getName(), Role.SUPERADMIN, TextFilterMethod.EQUALS))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.NameReserved, Role.SUPERADMIN));
		
		// cannot be SysAdmin role
		if (globalIsMatch(role.getName(), Role.SYSADMIN, TextFilterMethod.EQUALS))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.NameReserved, Role.SYSADMIN));
		
		// cannot be global role
		if (role.getTenant() == null)
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_SystemRoleErr));
	}
	
	private boolean rolenameIsUsed(final Role role) {
		return !roleRepo.findByName(role.getName()).isEmpty();
	}
	
	@PutMapping
	@Secured("MODIFY_ROLES")
	@Transactional
	public Role updateRole(@RequestHeader("X-TenantID") final int tenantId, @RequestBody final RoleUpdateDTO roleDto) {
		if (!roleRepo.existsById(roleDto.getId()))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleMissing, roleDto.getId()));
		
		final Role dbRole = roleRepo.findById(roleDto.getId()).get();
		final String oldName = dbRole.getName();
	
		final Role tempRole = new Role();
		tempRole.setTenant(dbRole.getTenant());
		tempRole.setName(processForStoring(roleDto.getName()));
		tempRole.setSystem(dbRole.isSystem());
		tempRole.setAuthorities(roleDto.getAuthorities());

		validateRole(tempRole);
		
		if (!Objects.equals(dbRole.getTenantId(), tenantId))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_RoleTenantMismatch, 
					dbRole.getTenantId(), tenantId));
		
		if (globalIsMatch(oldName, roleDto.getName(), TextFilterMethod.NOT_EQUALS) && rolenameIsUsed(tempRole))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_RoleExists));
		
		dbRole.setName(processForStoring(roleDto.getName()));
		//add new permissions
		dbRole.setAuthorities(roleDto.getAuthorities().stream()
				.filter(auth -> Authority.ALL_TENANT_AUTHORITIES.contains(auth))
				.collect(Collectors.toSet()));
		
		return roleRepo.save(dbRole);
	}
	
	@DeleteMapping("/{id}")
	@Secured("DELETE_ROLES")
	@Transactional
	public void deleteRole(@RequestHeader(value = "X-TenantID") final int tenantId, @PathVariable(name = "id") final long roleId) {
		if (!roleRepo.existsById(roleId))
			return;
		
		final Role toBeRemoved = roleRepo.findById(roleId).get();
		
		if (!Objects.equals(toBeRemoved.getTenantId(), tenantId))
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_RoleTenantMismatch, 
					toBeRemoved.getTenantId(), tenantId));
		
		if (toBeRemoved.isSystem())
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.RoleController_SystemRoleErr));
		
		userRepo.findAllByRolesContains(toBeRemoved).forEach(mu -> mu.getRoles().remove(toBeRemoved));
		roleRepo.delete(toBeRemoved);
	}
}
