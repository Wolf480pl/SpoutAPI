package org.spout.api.plugin.security;

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class OptOutPermission extends Permission {
	private final PermissionCollection excluded;

	public OptOutPermission(PermissionCollection excluded) {
		super("<almost all>");
		this.excluded = excluded;
	}

	@Override
	public boolean implies(Permission permission) {
		return !excluded.implies(permission);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof OptOutPermission) {
			return this.excluded.equals(((OptOutPermission) obj).excluded);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return excluded.hashCode();
	}

	@Override
	public String getActions() {
		return "";
	}

	@Override
	public PermissionCollection newPermissionCollection() {
		return new OptOutPermissionCollection();
	}

	static final class OptOutPermissionCollection extends PermissionCollection {
		CommonPermissionCollection excluded = new CommonPermissionCollection();

		@Override
		public void add(Permission permission) {
			if (!(permission instanceof OptOutPermission)) {
				throw new IllegalArgumentException("invalid permission: " + permission);
			}
			if (isReadOnly()) {
				throw new SecurityException("attempt to add a Permission to a readonly PermissionCollection");
			}
			OptOutPermission perm = (OptOutPermission) permission;
			excluded.addAll(perm.excluded);
		}

		@Override
		public boolean implies(Permission permission) {
			return !excluded.implies(permission);
		}

		@Override
		public Enumeration<Permission> elements() {
			List<Permission> list = new ArrayList<Permission>();
			CommonPermissionCollection perms = new CommonPermissionCollection();
			perms.addAll(excluded);
			list.add(new OptOutPermission(perms));
			return Collections.enumeration(list);
		}

	}
}
