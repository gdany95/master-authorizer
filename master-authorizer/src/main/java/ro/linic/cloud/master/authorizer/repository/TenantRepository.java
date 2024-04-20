package ro.linic.cloud.master.authorizer.repository;

import org.javers.spring.annotation.JaversSpringDataAuditable;
import org.springframework.data.jpa.repository.JpaRepository;

import ro.linic.cloud.master.authorizer.entity.Tenant;

@JaversSpringDataAuditable
public interface TenantRepository extends JpaRepository<Tenant, Integer> {
	boolean existsByName(String name);
}