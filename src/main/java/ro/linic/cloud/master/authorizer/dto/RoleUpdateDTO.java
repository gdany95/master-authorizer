package ro.linic.cloud.master.authorizer.dto;

import java.util.Set;

import lombok.Data;
import ro.linic.cloud.master.authorizer.entity.Authority;

@Data
public class RoleUpdateDTO {
	private long id;
	private String name;
	private Set<Authority> authorities = Set.of();
}
