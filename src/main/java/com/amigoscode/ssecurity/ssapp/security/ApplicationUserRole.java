package com.amigoscode.ssecurity.ssapp.security;

import com.google.common.collect.Sets;
import static com.amigoscode.ssecurity.ssapp.security.ApplicationUserPermission.*;
import java.util.Set;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));
	
	private final Set<ApplicationUserPermission> permissions;
	
	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
	
	
}
