package ro.linic.cloud.master.authorizer.repository;

import java.util.List;

import org.javers.spring.annotation.JaversSpringDataAuditable;
import org.springframework.data.jpa.repository.JpaRepository;

import ro.linic.cloud.master.authorizer.entity.Role;

@JaversSpringDataAuditable
public interface RoleRepository extends JpaRepository<Role, Long> {
	List<Role> findByName(String name);
}