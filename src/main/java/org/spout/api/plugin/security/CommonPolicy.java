package org.spout.api.plugin.security;

import java.io.File;
import java.io.FilePermission;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Enumeration;

import org.spout.api.plugin.CommonClassLoader;
import org.spout.api.plugin.Plugin;

public class CommonPolicy extends Policy {
	private ClassLoader spoutClassLoader = this.getClass().getClassLoader();
	private PermissionCollection defaultPluginPerms;

	//TODO: Long-ranged: Read plugin perms from YAML config, remove defaultPluginPerms var (replace with YAML section)

	public CommonPolicy(PermissionCollection defaultPluginPerms) {
		this.defaultPluginPerms = defaultPluginPerms;
	}

	@Override
	public PermissionCollection getPermissions(ProtectionDomain domain) {
		if (isSpout(domain)) {
			return new AllPermission().newPermissionCollection();
		} else {
			ClassLoader loader = domain.getClassLoader();
			while (!(loader instanceof CommonClassLoader)) {
				loader = loader.getParent();
			}
			CommonPermissionCollection perms = getPluginPermissions(((CommonClassLoader) loader).getPlugin());
			perms.addAll(domain.getPermissions()); // These domain static permissions are usually read perms for the codesource location.
			return perms;
		}
	}

	public CommonPermissionCollection getPluginPermissions(Plugin plugin) {
		CommonPermissionCollection perms = new CommonPermissionCollection();
		perms.addAll(defaultPluginPerms);
		perms.add(new FilePermission(plugin.getDataFolder().getAbsolutePath() + File.separator + "-", "read,write,delete"));
		return perms;
	}

	public boolean isSpout(ProtectionDomain domain) {
		return domain.getClassLoader() == spoutClassLoader;
	}

	public static class CommonPermissionCollection extends PermissionCollection {
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

		@Override
		public Enumeration<Permission> elements() {
			return perms.elements();
		}

	}


}
