package ro.linic.cloud.master.authorizer.controller;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
import ro.linic.util.commons.NumberUtils;

@RestController
@RequestMapping("/user")
public class UserController {
	@Autowired private I18n i18n;
	@Autowired private MultiUserRepository userRepository;
	private SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
	
	@GetMapping("/authorities")
    public List<GrantedAuthority> authorities(@AuthenticationPrincipal final AuthenticatedPrincipal principal,
    		@RequestHeader("X-TenantID") final int tenantId) {
        return userRepository.findById(NumberUtils.parseToInt(principal.getName()))
        		.or(() -> userRepository.findByPrincipal(principal.getName()))
        		.stream()
                .flatMap(t -> t.rolesOfTenant(tenantId))
                .flatMap(role -> role.getAuthorities().stream())
                .map(Authority::toString)
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableList());
    }
	
	@DeleteMapping
	public void deleteMyself(final Authentication authentication, final HttpServletRequest request,
			final HttpServletResponse response) {
		userRepository.deleteById(NumberUtils.parseToInt(authentication.getName()));
		this.logoutHandler.logout(request, response, authentication);
	}
	
	@DeleteMapping("/{id}")
	@Secured("DELETE_USERS")
	@Transactional
	public void removeFromCompany(@PathVariable(name = "id") final Integer id,
			@RequestHeader("X-TenantID") final int tenantId) {
		final Optional<MultiUser> userToRemove = userRepository.findById(id);
		
		if (userToRemove.isEmpty())
			return;
		
		userToRemove.get().rolesOfTenant(tenantId).collect(Collectors.toList()).forEach(role ->
		{
			if (role.getName().equalsIgnoreCase(Role.SUPERADMIN))
				throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SUPERADMIN));
			else if (role.getName().equalsIgnoreCase(Role.SYSADMIN))
				throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, i18n.msg(Messages.UserDelete_RoleNotPermits, Role.SYSADMIN));
			
			userToRemove.get().getRoles().remove(role);
		});
	}
}
