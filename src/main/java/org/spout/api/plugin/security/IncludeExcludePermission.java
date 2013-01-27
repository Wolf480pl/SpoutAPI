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

import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class IncludeExcludePermission extends Permission {
	private static final long serialVersionUID = -2675188463008189372L;
	private final PermissionCollection included;
	private final PermissionCollection excluded;

	public IncludeExcludePermission(PermissionCollection included, PermissionCollection excluded) {
		super("<include/exclude>");
		this.included = new CommonPermissionCollection(included);
		this.excluded = new CommonPermissionCollection(excluded);
	}

	public IncludeExcludePermission(PermissionCollection excluded) {
		super("<exclude>");
		this.included = new Permissions();
		this.included.add(new AllPermission());
		this.excluded = new CommonPermissionCollection(excluded);
	}

	@Override
	public boolean implies(Permission permission) {
		return included.implies(permission) && !excluded.implies(permission);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof IncludeExcludePermission) {
			IncludeExcludePermission that = (IncludeExcludePermission) obj;
			return that.implies(this) && this.implies(that);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return excluded.hashCode() ^ included.hashCode();
	}

	@Override
	public String getActions() {
		return "";
	}

	@Override
	public IncludeExcludePermissionCollection newPermissionCollection() {
		return new IncludeExcludePermissionCollection();
	}

	@Override
	public String toString() {
		return "( " + getClass().getName() + "\n" + "included: " + included.toString() + "excluded:" + excluded.toString() + ")";
	}

	static final class IncludeExcludePermissionCollection extends PermissionCollection {
		private static final long serialVersionUID = 3054629744490459143L;
		private final CommonPermissionCollection included = new CommonPermissionCollection();
		private final CommonPermissionCollection excluded = new CommonPermissionCollection();

		@Override
		public void add(Permission permission) {
			if (!(permission instanceof IncludeExcludePermission)) {
				throw new IllegalArgumentException("invalid permission: " + permission);
			}
			if (isReadOnly()) {
				throw new SecurityException("attempt to add a Permission to a readonly PermissionCollection");
			}
			IncludeExcludePermission perm = (IncludeExcludePermission) permission;
			included.addAll(perm.included);
			excluded.addAll(perm.excluded);
		}

		@Override
		public boolean implies(Permission permission) {
			return included.implies(permission) && !excluded.implies(permission);
		}

		@Override
		public Enumeration<Permission> elements() {
			List<Permission> list = new ArrayList<Permission>();
			list.add(new IncludeExcludePermission(excluded));
			return Collections.enumeration(list);
		}

		@Override
		public String toString() {
			return "( " + getClass().getName() + "\n" + "included: " + included.toString() + "excluded:" + excluded.toString() + ")";
		}
	}
}
