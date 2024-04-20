package ro.linic.cloud.master.authorizer.controller;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.common.I18n;
import ro.linic.cloud.master.authorizer.entity.Authority;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.util.commons.NumberUtils;

@RestController
@RequestMapping("/user")
public class UserController {
	@Autowired private I18n i18n;
	@Autowired private MultiUserRepository userRepository;
	@Autowired private RoleRepository roleRepo;
	private SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
	
	@GetMapping("/authorities")
    public Set<Authority> authorities(@AuthenticationPrincipal final AuthenticatedPrincipal principal,
    		@RequestHeader("X-TenantID") final int tenantId) {
        return findUser(principal.getName())
        		.stream()
                .flatMap(u -> u.authoritiesOfTenantAndGlobal(tenantId))
                .collect(Collectors.toSet());
    }
	
	private Optional<MultiUser> findUser(final String principalName) {
		return userRepository.findById(NumberUtils.parseToInt(principalName))
        		.or(() -> userRepository.findByPrincipal(principalName));
	}
	
	@DeleteMapping
	@Transactional
	public void deleteMyself(final Authentication authentication, final HttpServletRequest request,
			final HttpServletResponse response) {
		findUser(authentication.getName()).ifPresent(userRepository::delete);
		this.logoutHandler.logout(request, response, authentication);
	}
	
	@DeleteMapping("/{id}")
	@Secured("DELETE_USERS")
	@Transactional
	public void removeFromTenant(@PathVariable(name = "id") final Integer id,
			@RequestHeader("X-TenantID") final int tenantId) {
		final Optional<MultiUser> userToRemove = userRepository.findById(id);
		
		if (userToRemove.isEmpty())
			return;
		
		userToRemove.get().rolesOfTenant(tenantId).collect(Collectors.toList()).forEach(role ->
		{
			if (role.isSuperAdmin())
				throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SUPERADMIN));
			else if (role.isSysAdmin())
				throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SYSADMIN));
			
			userToRemove.get().getRoles().remove(role);
		});
	}
	
	@PutMapping("/{id}/roles")
	@Secured("MODIFY_USER_ROLES")
	@Transactional
	public void modifyUserRoles(@AuthenticationPrincipal final AuthenticatedPrincipal principal, @RequestHeader("X-TenantID") final int tenantId,
			@PathVariable(name = "id") final Integer id, @RequestBody final Set<Long> roleIds) {
		final Optional<MultiUser> userToChange = userRepository.findById(id);
		
		if (userToChange.isEmpty())
			return;
		
		final MultiUser loggedUser = findUser(principal.getName()).get();
		
		final Set<Role> newRoles = roleRepo.findAllById(roleIds).stream().collect(Collectors.toSet());
		final Set<Role> oldRoles = userToChange.get().rolesOfTenant(tenantId).collect(Collectors.toSet());
		
		validateRoleChange(tenantId, loggedUser, userToChange.get(), oldRoles, newRoles);
		
		userToChange.get().getRoles().removeAll(oldRoles);
		userToChange.get().getRoles().addAll(newRoles);
	}
	
	private void validateRoleChange(final int tenantId, final MultiUser loggedUser, final MultiUser userToChange, final Set<Role> oldRoles,
			final Set<Role> newRoles)
	{
		if (newRoles.stream().anyMatch(Role::isSuperAdmin) && loggedUser.rolesOfTenant(tenantId).noneMatch(Role::isSuperAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_SuperadminRequired, Role.SUPERADMIN));
		
		if (oldRoles.stream().anyMatch(Role::isSuperAdmin) && loggedUser.rolesOfTenant(tenantId).noneMatch(Role::isSuperAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_SuperadminChangeAnother, Role.SUPERADMIN));
		
		if (newRoles.stream().anyMatch(Role::isSysAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_RoleReserved, Role.SYSADMIN));

		if (oldRoles.stream().anyMatch(Role::isSysAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_ChangeNotAllowed, Role.SYSADMIN));
		
		if (newRoles.stream().anyMatch(r -> r.getTenantId() == null))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_GlobalRoleNotAllowed));
		
		if (oldRoles.stream().anyMatch(r -> r.getTenantId() != tenantId) || newRoles.stream().anyMatch(r -> r.getTenantId() != tenantId))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.TenantMismatch));
	}
	
	@PutMapping
	@Transactional
	public void changeName(final Authentication authentication, @RequestBody final String name) {
		final MultiUser me = findUser(authentication.getName()).get();
		me.setDisplayName(name);
	}
}
