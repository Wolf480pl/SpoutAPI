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
