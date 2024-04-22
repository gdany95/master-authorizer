package ro.linic.cloud.master.authorizer.entity;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.HashSet;
import java.util.Set;

import org.hibernate.annotations.Type;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Entity
@Data
public class InviteToken {
	private static final TemporalAmount EXPIRATION = Duration.ofHours(24);

    @Id
    @Column(unique = true, nullable = false)
    private String token;
  
    @ManyToOne
	@JoinColumn(name = "tenant_id", nullable = false)
	private Tenant tenant;
    
    @Type(JsonBinaryType.class)
	@Column(columnDefinition = "jsonb")
	private Set<Long> roles = new HashSet<>();
    
    private Instant expiryDate = Instant.now().plus(EXPIRATION);
    
    public boolean isExpired() {
    	return getExpiryDate().isBefore(Instant.now());
    }
}
