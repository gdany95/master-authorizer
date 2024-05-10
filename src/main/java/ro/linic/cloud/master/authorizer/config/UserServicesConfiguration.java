package ro.linic.cloud.master.authorizer.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.transaction.annotation.Transactional;

import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.java.Log;
import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.repository.MultiUserRepository;
import ro.linic.cloud.master.authorizer.repository.RoleRepository;

@Configuration
@NoArgsConstructor @ToString @Log
public class UserServicesConfiguration {
    @Autowired private RoleRepository roleRepository;
    @Autowired private MultiUserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new OAuth2UserServiceImpl();
    }

    @Bean
    public OidcUserService oidcUserService() {
        return new OidcUserServiceImpl();
    }

    @NoArgsConstructor @ToString
    private class UserDetailsServiceImpl implements UserDetailsService {
        @Override
        @Transactional(readOnly = true)
        public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
            UserDetails user = null;

            try {
                final MultiUser multiUser =
                		userRepository.findByPrincipal(username)
                    .orElseThrow(() -> new UsernameNotFoundException(username));

                user = User.builder()
                      .username(String.valueOf(multiUser.getId()))
                      .password(multiUser.getPassword())
                      .build();
            } catch (final UsernameNotFoundException exception) {
                throw exception;
            }

            return user;
        }
    }

    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils.NO_AUTHORITIES;

    @NoArgsConstructor @ToString
    private class OAuth2UserServiceImpl extends DefaultOAuth2UserService {
        private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        @Override
        @Transactional
        public OAuth2User loadUser(final OAuth2UserRequest request) throws OAuth2AuthenticationException {
            final String nameAttribute =
                request.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();
            final OAuth2User user = delegate.loadUser(request);
            
            final MultiUser multiUser = userRepository.findByPrincipal(user.getName())
            		.orElseGet(() -> userRepository.save(MultiUser.builder().principals(Set.of(user.getName())).build()));
            final Map<String, Object> attributes = new HashMap<>(user.getAttributes());
            attributes.replace(nameAttribute, String.valueOf(multiUser.getId()));
            
            return new DefaultOAuth2User(DEFAULT_AUTHORITIES, attributes, nameAttribute);
        }
    }

    @NoArgsConstructor @ToString
    private class OidcUserServiceImpl extends OidcUserService {
        { setOauth2UserService(oAuth2UserService()); }

        @Override
        @Transactional
        public OidcUser loadUser(final OidcUserRequest request) throws OAuth2AuthenticationException {
            final String nameAttribute =
                request.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();
            final OidcUser user = super.loadUser(request);
            
            final MultiUser multiUser = userRepository.findByPrincipal(user.getName())
            		.orElseGet(() -> userRepository.save(MultiUser.builder().principals(Set.of(user.getName())).displayName(user.getFullName()).build()));
            final OidcIdToken idToken = OidcIdToken.withTokenValue(user.getIdToken().getTokenValue())
            		.claim(nameAttribute, String.valueOf(multiUser.getId()))
            		.build();
            
            return new DefaultOidcUser(DEFAULT_AUTHORITIES, idToken, user.getUserInfo(), nameAttribute);
        }
    }
}