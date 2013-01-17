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