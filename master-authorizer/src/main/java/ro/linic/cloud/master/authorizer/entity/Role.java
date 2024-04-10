package ro.linic.cloud.master.authorizer.entity;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.hibernate.annotations.Type;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import ro.linic.cloud.master.authorizer.Messages;
import ro.linic.cloud.master.authorizer.common.I18n;

@Entity
@Data
public class Role {
	public static final String SYSADMIN = "SysAdmin";
	public static final String SUPERADMIN = "Administrator";
	
	public static String authoritiesToText(final Set<Authority> authorities, final String separator, final I18n i18n)
	{
		if (authorities.isEmpty())
			return i18n.msg(Messages.None);
		
		if (authorities.containsAll(Authority.ALL_TENANT_AUTHORITIES))
			return i18n.msg(Messages.All);
		
		return authorities.stream()
				.map(Authority::toString)
				.map(i18n::msg)
				.sorted()
				.collect(Collectors.joining(separator));
	}
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	@Column(nullable = false)
	@NotBlank
	private String name;
	
	/**
	 * A system role cannot be deleted/modified/created by users
	 */
	@Column(columnDefinition="BOOLEAN DEFAULT false")
	@NotNull
	private boolean isSystem = false;
	
	/*
	 * If tenant is null, this role is a global role
	 */
	@ManyToOne
	@JoinColumn(name = "tenant_id", nullable = true)
	private Tenant tenant;
	
	@Type(JsonBinaryType.class)
	@Column(columnDefinition = "jsonb")
	private Set<Authority> authorities = new HashSet<>();
	
	public Integer getTenantId() {
		return tenant != null ? tenant.getId() : null;
	}
}
