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

import java.io.File;
import java.io.FilePermission;
import java.net.SocketPermission;
import java.security.AccessController;
import java.security.AllPermission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.util.List;
import java.util.logging.Level;

import org.spout.api.Engine;
import org.spout.api.exception.ConfigurationException;
import org.spout.api.plugin.CommonClassLoader;
import org.spout.api.plugin.Plugin;
import org.spout.api.plugin.PluginDescriptionFile;
import org.spout.api.plugin.security.IncludeExcludePermission.IncludeExcludePermissionCollection;
import org.spout.api.util.config.ConfigurationNode;
import org.spout.api.util.config.yaml.YamlConfiguration;

public class CommonPolicy extends Policy {
	private ClassLoader spoutClassLoader;
	private PermissionCollection defaultPluginPerms;
	private YamlConfiguration config;
	private Engine engine;

	public CommonPolicy(Engine engine, File configFile) {
		this.engine = engine;
		this.spoutClassLoader = engine.getClass().getClassLoader();
		this.defaultPluginPerms = getDefaultPluginPerms();
		this.config = new YamlConfiguration(configFile);
		config.setHeader("This is configuration file for client plugin clearances.",
				"It is not recommended to edit this file manually. Use the launcher GUI instead.");
		load();
	}

	@Override
	public PermissionCollection getPermissions(final ProtectionDomain domain) {
		return AccessController.doPrivileged(new PrivilegedAction<PermissionCollection>() {
			@Override
			public PermissionCollection run() {
				if (isSpout(domain)) {
					return new AllPermission().newPermissionCollection();
				} else {
					ClassLoader loader = domain.getClassLoader();
					while (loader != null) {
						if (loader instanceof CommonClassLoader) {
							CommonPermissionCollection perms = getPluginPermissions(((CommonClassLoader) loader).getPlugin());
							perms.addAll(domain.getPermissions()); // These domain static permissions are usually read perms for the codesource location.

							IncludeExcludePermissionCollection includeExclude = new IncludeExcludePermissionCollection();
							includeExclude.add(new IncludeExcludePermission(perms, getPluginExcludedPerms()));
							return includeExclude;
						}
						loader = loader.getParent();
					}
				}
				return null;
			}
		});
	}

	@Override
	public void refresh() {
		load();
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

	public void checkPluginLoad(PluginDescriptionFile desc, File dataFolder) throws InsufficientClearancesException {
		ConfigurationNode clearances = desc.getRequiredClearances();
		CommonPermissionCollection required = new CommonPermissionCollection();
		if (clearances != null) {
			if (clearances.hasChild("filesystem")) {
				required.addAll(parseFilesystem(clearances.getChild("filesystem")));
			}
			if (clearances.hasChild("network")) {
				required.addAll(parseNetwork(clearances.getChild("network")));
			}
			if (clearances.hasChild("browser")) {
				required.addAll(parseBrowser(clearances.getChild("browser")));
			}
		}
		if (!getPluginPermissions(desc, dataFolder).impliesAll(required)) {
			throw new InsufficientClearancesException();
		}
	}

	protected CommonPermissionCollection getPluginPermissions(Plugin plugin) {
		return getPluginPermissions(plugin.getDescription(), plugin.getDataFolder());
	}

	protected CommonPermissionCollection getPluginPermissions(PluginDescriptionFile desc, File dataFolder) {
		CommonPermissionCollection perms = new CommonPermissionCollection();
		perms.addAll(defaultPluginPerms);
		perms.add(new FilePermission(dataFolder.getAbsolutePath() + File.separator + "-", "read,write,delete"));

		ConfigurationNode pluginNode = config.getChild(desc.getName());
		if (pluginNode != null) {
			if (pluginNode.hasChild("filesystem")) {
				perms.addAll(parseFilesystem(pluginNode.getChild("filesystem")));
			}
			if (pluginNode.hasChild("network")) {
				perms.addAll(parseNetwork(pluginNode.getChild("network")));
			}
			if (pluginNode.hasChild("browser")) {
				perms.addAll(parseBrowser(pluginNode.getChild("browser")));
			}
		}
		return perms;
	}

	protected boolean isSpout(ProtectionDomain domain) {
		return domain.getClassLoader() == spoutClassLoader;
	}

	protected static PermissionCollection getDefaultPluginPerms() {
		Permissions perms = new Permissions();
		perms.add(new RuntimePermission("getClassLoader"));
		perms.add(new RuntimePermission("accessDeclaredMembers"));
		perms.add(new SecurityPermission("getPolicy"));
		perms.add(new SecurityPermission("insertProvider.SunJSSE"));
		// TODO: Add more here.
		return perms;
	}

	protected PermissionCollection getPluginExcludedPerms() {
		Permissions perms = new Permissions();
		perms.add(new FilePermission(config.getFile().getPath(), "read,write,execute,delete"));
		perms.add(new FilePermission(engine.getClass().getProtectionDomain().getCodeSource().getLocation().getFile(), "read,write,execute,delete"));
		// TODO: Add lastlogin here.
		return perms;
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
				BrowserPermission perm = new BrowserPermission((String) o);
				if (collection == null) {
					collection = perm.newPermissionCollection();
				}
				collection.add(perm);
			}
		}
		return collection;
	}
}
