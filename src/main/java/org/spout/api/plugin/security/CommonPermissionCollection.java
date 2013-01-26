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
import java.security.Permissions;
import java.util.Enumeration;

public class CommonPermissionCollection extends PermissionCollection {
	private static final long serialVersionUID = -2131850295013966510L;
	private Permissions perms;

	public CommonPermissionCollection() {
		perms = new Permissions();
	}

	public CommonPermissionCollection(PermissionCollection collection) {
		this();
		addAll(collection);
	}

	public void addAll(PermissionCollection collection) {
		if (collection == null) {
			return;
		}
		Enumeration<Permission> e = collection.elements();
		while (e.hasMoreElements()) {
			add(e.nextElement());
		}
	}

	@Override
	public void add(Permission permission) {
		perms.add(permission);
	}

	@Override
	public boolean implies(Permission permission) {
		return perms.implies(permission);
	}

	public boolean impliesAll(PermissionCollection collection) {
		Enumeration<Permission> elements = collection.elements();
		while (elements.hasMoreElements()) {
			if (!implies(elements.nextElement())) {
				return false;
			}
		}
		return true;
	}

	@Override
	public Enumeration<Permission> elements() {
		return perms.elements();
	}

}