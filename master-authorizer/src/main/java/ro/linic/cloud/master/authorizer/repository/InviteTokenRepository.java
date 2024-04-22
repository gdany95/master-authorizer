package ro.linic.cloud.master.authorizer.repository;

import java.time.Instant;
import java.util.List;

import org.javers.spring.annotation.JaversSpringDataAuditable;
import org.springframework.data.jpa.repository.JpaRepository;

import ro.linic.cloud.master.authorizer.entity.InviteToken;

@JaversSpringDataAuditable
public interface InviteTokenRepository extends JpaRepository<InviteToken, String> {
	List<InviteToken> findAllByExpiryDateBefore(Instant before);
}