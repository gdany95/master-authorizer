package ro.linic.cloud.master.authorizer.repository;

import java.util.List;

import org.javers.spring.annotation.JaversSpringDataAuditable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import ro.linic.cloud.master.authorizer.entity.Role;

@JaversSpringDataAuditable
public interface RoleRepository extends JpaRepository<Role, Long> {
	List<Role> findByName(String name);
	@Modifying
	@Query(value = "DELETE FROM multi_user_role WHERE multi_user_role.role_id = :id", nativeQuery = true)
	void deleteUserConnections(@Param("id") long id);
}