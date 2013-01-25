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

import java.io.Serializable;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class BrowserPermission extends Permission implements Serializable {

	private boolean wildcard;
	private String cname;

	public BrowserPermission(String name) {
		super(name);
		init(name);
	}

	public BrowserPermission(String name, String actions) {
		super(name);
		init(name);
	}

	private void init(String host) {
		if (host == null) {
			throw new NullPointerException("host can't be null");
		}
		if (host.length() == 0) {
			throw new IllegalArgumentException("host can't be empty");
		}
		if (host.lastIndexOf('*') > 0) {
			throw new IllegalArgumentException("invalid host wildcard specification");
		} else if (host.startsWith("*")) {
			wildcard = true;
			if (host.equals("*")) {
				cname = "";
			} else if (host.startsWith("*.")) {
				cname = host.substring(1).toLowerCase();
			} else {
				throw new IllegalArgumentException("invalid host wildcard specification");
			}
			return;
		}
		cname = host.toLowerCase();
	}

	@Override
	public boolean implies(Permission p) {
		if ((p == null) || !(p instanceof BrowserPermission)) {
			return false;
		}
		BrowserPermission that = (BrowserPermission) p;
		if (this.wildcard) {
			if (that.wildcard) {
				return that.cname.endsWith(cname);
			} else {
				return (that.cname.length() > this.cname.length()) && that.cname.startsWith(this.cname);
			}
		} else {
			if (that.wildcard) {
				return false;
			} else {
				return this.cname.equals(that.cname);
			}
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || !(obj instanceof BrowserPermission)) {
			return false;
		}
		BrowserPermission p = (BrowserPermission) obj;
		return this.cname.equals(p.cname);
	}

	@Override
	public int hashCode() {
		return this.cname.hashCode();
	}

	@Override
	public String getActions() {
		return "";
	}

	@Override
	public PermissionCollection newPermissionCollection() {
		return new BrowserPermissionCollection();
	}

	static final class BrowserPermissionCollection extends PermissionCollection implements Serializable {
		private Map<String, Permission> perms;
		private boolean allAllowed;

		public BrowserPermissionCollection() {
			perms = new HashMap<String, Permission>();
			allAllowed = false;
		}

		@Override
		public void add(Permission permission) {
			if (!(permission instanceof BrowserPermission)) {
				throw new IllegalArgumentException("invalid permission: " + permission);
			}
			if (isReadOnly()) {
				throw new SecurityException("attempt to add a Permission to a readonly PermissionCollection");
			}
			BrowserPermission p = (BrowserPermission) permission;
			synchronized (this) {
				perms.put(p.cname, p);
			}
			if (p.cname.equals("*")) {
				allAllowed = true;
			}

		}

		@Override
		public boolean implies(Permission permission) {
			if (!(permission instanceof BrowserPermission)) {
				return false;
			}
			BrowserPermission p = (BrowserPermission) permission;
			if (allAllowed) {
				return true;
			}
			String path = p.cname;
			Permission x;
			synchronized (this) {
				x = perms.get(path);
			}
			if (x != null) {
				return x.implies(permission);
			}
			int offset = path.indexOf('.', 1);
			while (offset != -1) {
				path = path.substring(offset);
				synchronized (this) {
					x = perms.get(path);
				}
				if (x != null) {
					return x.implies(permission);
				}
				offset = path.indexOf('.', 1);
			}
			return false;
		}

		@Override
		public Enumeration<Permission> elements() {
			synchronized (this) {
				return Collections.enumeration(perms.values());
			}
		}

	}
}
