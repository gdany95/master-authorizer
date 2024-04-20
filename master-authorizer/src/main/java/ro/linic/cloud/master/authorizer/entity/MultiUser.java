package ro.linic.cloud.master.authorizer.entity;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.hibernate.annotations.Type;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data @NoArgsConstructor @AllArgsConstructor @Builder
public class MultiUser {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	
    @Type(JsonBinaryType.class)
	@Column(columnDefinition = "jsonb", unique = true)
	@Builder.Default
    private Set<String> principals = new HashSet<>();
	
	@Column(columnDefinition = "text", nullable = true)
    private String password;
	private String displayName;
	
	@ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.LAZY)
	@JoinTable(name = "multi_user_role",
	    joinColumns = {@JoinColumn(name = "multi_user_id")},
	    inverseJoinColumns = {@JoinColumn(name = "role_id")})
	@Builder.Default
	private Set<Role> roles = new HashSet<>();
	
	public Stream<Role> rolesOfTenant(final int tenantId)
	{
		return getRoles().stream()
				.filter(role -> role.getTenantId() != null && role.getTenantId() == tenantId);
	}

	public Stream<Role> globalRoles() {
		return getRoles().stream()
				.filter(role -> role.getTenant() == null);
	}

	public Stream<Authority> allAuthorities() {
		return getRoles().stream()
				.flatMap(r -> r.getAuthorities().stream())
				.distinct();
	}
	
	public Stream<Authority> authoritiesOfTenantAndGlobal(final int tenantId) {
		return getRoles().stream()
				.filter(role -> role.getTenant() == null || Objects.equals(role.getTenantId(), tenantId))
				.flatMap(r -> r.getAuthorities().stream())
				.distinct();
	}
}
