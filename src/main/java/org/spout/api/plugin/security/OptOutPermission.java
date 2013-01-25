/*
 * This file is part of SpoutAPI.
 *
 * Copyright (c) 2011-2012, Spout LLC <http://www.spout.org/>
 * SpoutAPI is licensed under the Spout License Version 1.
 *
 * SpoutAPI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * In addition, 180 days after any changes are published, you can use the
 * software, incorporating those changes, under the terms of the MIT license,
 * as described in the Spout License Version 1.
 *
 * SpoutAPI is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License,
 * the MIT license and the Spout License Version 1 along with this program.
 * If not, see <http://www.gnu.org/licenses/> for the GNU Lesser General Public
 * License and see <http://spout.in/licensev1> for the full license, including
 * the MIT license.
 */
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
