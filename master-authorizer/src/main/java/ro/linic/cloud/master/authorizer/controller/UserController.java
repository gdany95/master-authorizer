package ro.linic.cloud.master.authorizer.controller;

import static ro.linic.util.commons.PresentationUtils.EMPTY_STRING;

import java.util.HashSet;
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
import org.springframework.web.bind.annotation.PostMapping;
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
import ro.linic.cloud.master.authorizer.entity.InviteToken;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;
import ro.linic.cloud.master.authorizer.entity.Tenant;
import ro.linic.cloud.master.authorizer.repository.InviteTokenRepository;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;
import ro.linic.cloud.master.authorizer.repository.TenantRepository;
import ro.linic.util.commons.NumberUtils;
import ro.linic.util.commons.PasswordGenerator;

@RestController
@RequestMapping("/user")
public class UserController {
	@Autowired private I18n i18n;
	@Autowired private TenantRepository tenantRepo;
	@Autowired private MultiUserRepository userRepo;
	@Autowired private RoleRepository roleRepo;
	@Autowired private InviteTokenRepository tokenRepo;
	private SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
	
	@GetMapping
    public String user(final Authentication principal) {
        return findUser(principal.getName())
                .map(MultiUser::getDisplayName)
                .orElse(EMPTY_STRING);
    }
	
	@GetMapping("/authorities")
    public Set<Authority> authorities(final Authentication principal,
    		@RequestHeader("X-TenantID") final int tenantId) {
        return findUser(principal.getName())
        		.stream()
                .flatMap(u -> u.authoritiesOfTenantAndGlobal(tenantId))
                .collect(Collectors.toSet());
    }
	
	@Secured("SCOPE_authorities.read")
	@GetMapping("/{principal}/authorities")
    public Set<Authority> userAuthorities(@PathVariable final String principal,
    		@RequestHeader("X-TenantID") final int tenantId) {
        return findUser(principal)
        		.stream()
                .flatMap(u -> u.authoritiesOfTenantAndGlobal(tenantId))
                .collect(Collectors.toSet());
    }
	
	private Optional<MultiUser> findUser(final String principalName) {
		return userRepo.findById(NumberUtils.parseToInt(principalName))
        		.or(() -> userRepo.findByPrincipal(principalName));
	}
	
	@DeleteMapping
	@Transactional
	public void deleteMyself(final Authentication authentication, final HttpServletRequest request,
			final HttpServletResponse response) {
		findUser(authentication.getName()).ifPresent(userRepo::delete);
		this.logoutHandler.logout(request, response, authentication);
	}
	
	@DeleteMapping("/{id}")
	@Secured("DELETE_USERS")
	@Transactional
	public void removeFromTenant(@PathVariable(name = "id") final Integer id,
			@RequestHeader("X-TenantID") final int tenantId) {
		final Optional<MultiUser> userToRemove = userRepo.findById(id);
		
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
	
	@PostMapping
	@Secured("CREATE_USERS")
	@Transactional
	public String inviteToTenant(final Authentication principal, @RequestHeader("X-TenantID") final int tenantId,
			@RequestBody final Set<Long> roleIds) {
		final Optional<Tenant> tenant = tenantRepo.findById(tenantId);
		
		if (tenant.isEmpty())
			throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED, i18n.msg(Messages.TenantMissing, tenantId));
		
		final MultiUser loggedUser = findUser(principal.getName()).get();
		final Set<Role> newRoles = roleRepo.findAllById(roleIds).stream().collect(Collectors.toSet());
		
		validateRoleChange(tenantId, loggedUser, Set.of(), newRoles);
		
        final InviteToken token = new InviteToken();
        token.setTenant(tenant.get());
        token.setRoles(new HashSet<>(roleIds));
        token.setToken(PasswordGenerator.withDefaults().generate(32));
        return tokenRepo.save(token).getToken();
	}
	
	@GetMapping("/accept/{token}")
	@Transactional
	public InviteToken getInvite(@PathVariable(name = "token") final String token) {
        return tokenRepo.findById(token).orElse(null);
	}
	
	@PostMapping("/accept/{token}")
	@Transactional
	public String acceptInvite(final Authentication principal, @PathVariable(name = "token") final String token) {
	    final Optional<InviteToken> inviteToken = tokenRepo.findById(token);
	    
	    if (inviteToken.isEmpty())
	    	throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.InviteTokenInvalid));
	    if (inviteToken.get().isExpired())
	    	throw new ResponseStatusException(HttpStatus.BAD_REQUEST, i18n.msg(Messages.InviteTokenInvalid));
	    
	    final MultiUser loggedUser = findUser(principal.getName()).get();
	    final Set<Role> newRoles = roleRepo.findAllById(inviteToken.get().getRoles()).stream().collect(Collectors.toSet());
	    loggedUser.getRoles().addAll(newRoles);
	    tokenRepo.delete(inviteToken.get());
        return "OK";
	}
	
	@PutMapping("/{id}/roles")
	@Secured("MODIFY_USER_ROLES")
	@Transactional
	public void modifyUserRoles(@AuthenticationPrincipal final AuthenticatedPrincipal principal, @RequestHeader("X-TenantID") final int tenantId,
			@PathVariable(name = "id") final Integer id, @RequestBody final Set<Long> roleIds) {
		final Optional<MultiUser> userToChange = userRepo.findById(id);
		
		if (userToChange.isEmpty())
			return;
		
		final MultiUser loggedUser = findUser(principal.getName()).get();
		
		final Set<Role> newRoles = roleRepo.findAllById(roleIds).stream().collect(Collectors.toSet());
		final Set<Role> oldRoles = userToChange.get().rolesOfTenant(tenantId).collect(Collectors.toSet());
		
		validateRoleChange(tenantId, loggedUser, oldRoles, newRoles);
		
		userToChange.get().getRoles().removeAll(oldRoles);
		userToChange.get().getRoles().addAll(newRoles);
	}
	
	private void validateRoleChange(final int tenantId, final MultiUser loggedUser, final Set<Role> oldRoles, final Set<Role> newRoles)
	{
		// Only SUPERADMIN can assign SUPERADMIN roles!
		if (newRoles.stream().anyMatch(Role::isSuperAdmin) && loggedUser.rolesOfTenant(tenantId).noneMatch(Role::isSuperAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_SuperadminRequired, Role.SUPERADMIN));
		
		// Only a SUPERADMIN can change another SUPERADMIN!
		if (oldRoles.stream().anyMatch(Role::isSuperAdmin) && loggedUser.rolesOfTenant(tenantId).noneMatch(Role::isSuperAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_SuperadminChangeAnother, Role.SUPERADMIN));
		
		// Role SYSADMIN is reserved!
		if (newRoles.stream().anyMatch(Role::isSysAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_RoleReserved, Role.SYSADMIN));

		// Role SYSADMIN cannot be changed!
		if (oldRoles.stream().anyMatch(Role::isSysAdmin))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_ChangeNotAllowed, Role.SYSADMIN));
		
		// Global roles are not allowed!
		if (newRoles.stream().anyMatch(r -> r.getTenantId() == null))
			throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserController_GlobalRoleNotAllowed));
		
		// Tenant ids must match!
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
