package ro.linic.cloud.master.authorizer.repository;

import java.util.List;
import java.util.Optional;

import org.javers.spring.annotation.JaversSpringDataAuditable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import ro.linic.cloud.master.authorizer.entity.MultiUser;
import ro.linic.cloud.master.authorizer.entity.Role;

@JaversSpringDataAuditable
public interface MultiUserRepository extends JpaRepository<MultiUser, Integer> {
	@Query(value = "SELECT * FROM multi_user WHERE principals @> to_jsonb(:principal) LIMIT 1", nativeQuery = true)
	Optional<MultiUser> findByPrincipal(@Param("principal") String principal);
	List<MultiUser> findAllByRolesContains(Role role);
}