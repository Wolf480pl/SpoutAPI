package org.spout.api.plugin.security;

import java.io.File;
import java.io.FilePermission;
import java.net.SocketPermission;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

import org.spout.api.Engine;
import org.spout.api.exception.ConfigurationException;
import org.spout.api.plugin.CommonClassLoader;
import org.spout.api.plugin.Plugin;
import org.spout.api.util.config.ConfigurationNode;
import org.spout.api.util.config.yaml.YamlConfiguration;

public class CommonPolicy extends Policy {
	private ClassLoader spoutClassLoader;
	private PermissionCollection defaultPluginPerms;
	private YamlConfiguration config;
	private Engine engine;

	public CommonPolicy(Engine engine, PermissionCollection defaultPluginPerms, File configFile) {
		this.engine = engine;
		this.spoutClassLoader = engine.getClass().getClassLoader();
		this.defaultPluginPerms = defaultPluginPerms;
		this.config = new YamlConfiguration(configFile);
		config.setHeader("This is configuration file for client plugin clearances.",
				"It is not recommended to edit this file manually. Use the launcher GUI instead.");
		load();
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

		ConfigurationNode pluginNode = config.getChild(plugin.getName());
		if (pluginNode != null) {
			perms.addAll(parseFilesystem(pluginNode.getChild("filesystem")));
			perms.addAll(parseNetwork(pluginNode.getChild("network")));
			perms.addAll(parseBrowser(pluginNode.getChild("browser")));
		}
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

	public void load() {
		try {
			config.load();
			config.save();
		} catch (ConfigurationException e) {
			engine.getLogger().log(Level.SEVERE, "Error loading clearance configuration!", e);
		}
	}

	public void save() {
		try {
			config.save();
		} catch (ConfigurationException e) {
			engine.getLogger().log(Level.SEVERE, "Error saving clearance configuration!", e);
		}
	}

	private PermissionCollection parseFilesystem(ConfigurationNode node) {
		if (node == null) {
			return null;
		}
		List<?> nodes = node.getList();
		PermissionCollection collection = null;
		for (Object o : nodes) {
			if (o instanceof String) {
				FilePermission perm = new FilePermission((String) o, "read,write,delete");
				if (collection == null) {
					collection = perm.newPermissionCollection();
				}
				collection.add(perm);
			}
		}
		return collection;
	}

	private PermissionCollection parseNetwork(ConfigurationNode node) {
		if (node == null) {
			return null;
		}
		List<?> nodes = node.getList();
		PermissionCollection collection = null;
		for (Object o : nodes) {
			if (o instanceof String) {
				SocketPermission perm = new SocketPermission((String) o, "connect,accept");
				if (collection == null) {
					collection = perm.newPermissionCollection();
				}
				collection.add(perm);
			}
		}
		return collection;
	}

	private PermissionCollection parseBrowser(ConfigurationNode node) {
		if (node == null) {
			return null;
		}
		List<?> nodes = node.getList();
		PermissionCollection collection = null;
		for (Object o : nodes) {
			if (o instanceof String) {
				// TODO: Make some permission class for opening browser.
			}
		}
		return collection;
	}
}
