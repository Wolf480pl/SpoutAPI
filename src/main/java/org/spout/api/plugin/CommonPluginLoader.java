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
package org.spout.api.plugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Policy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.regex.Pattern;

import org.apache.commons.collections.map.CaseInsensitiveMap;

import org.spout.api.Engine;
import org.spout.api.Spout;
import org.spout.api.UnsafeMethod;
import org.spout.api.event.server.plugin.PluginDisableEvent;
import org.spout.api.event.server.plugin.PluginEnableEvent;
import org.spout.api.exception.InvalidDescriptionFileException;
import org.spout.api.exception.InvalidPluginException;
import org.spout.api.exception.UnknownDependencyException;
import org.spout.api.exception.UnknownSoftDependencyException;
import org.spout.api.plugin.security.CommonPolicy;
import org.spout.api.plugin.security.InsufficientClearancesException;

public class CommonPluginLoader implements PluginLoader {
	public static final String YAML_SPOUT = "properties.yml";
	public static final String YAML_OTHER = "plugin.yml";
	protected final Engine engine;
	private final Pattern[] patterns;
	@SuppressWarnings("unchecked")
	private final Map<String, CommonClassLoader> loaders = new CaseInsensitiveMap();

	public CommonPluginLoader(final Engine engine) {
		this.engine = engine;
		this.patterns = new Pattern[]{Pattern.compile("\\.jar$")};
	}

	@Override
	public Pattern[] getPatterns() {
		return this.patterns;
	}

	@Override
	@UnsafeMethod
	public synchronized void enablePlugin(Plugin plugin) {
		if (!CommonPlugin.class.isAssignableFrom(plugin.getClass())) {
			throw new IllegalArgumentException("Cannot enable plugin with this PluginLoader as it is of the wrong type!");
		}
		if (!plugin.isEnabled()) {
			CommonPlugin cp = (CommonPlugin) plugin;
			String name = cp.getDescription().getName();

			if (!this.loaders.containsKey(name)) {
				this.loaders.put(name, (CommonClassLoader) cp.getClassLoader());
			}

			try {
				cp.setEnabled(true);
				cp.onEnable();
			} catch (Throwable e) {
				this.engine.getLogger().log(Level.SEVERE, "An error occured when enabling '" + plugin.getDescription().getFullName() + "': " + e.getMessage(), e);
			}

			this.engine.getEventManager().callEvent(new PluginEnableEvent(cp));
		}
	}

	@Override
	@UnsafeMethod
	public synchronized void disablePlugin(Plugin paramPlugin) {
		if (!CommonPlugin.class.isAssignableFrom(paramPlugin.getClass())) {
			throw new IllegalArgumentException("Cannot disable plugin with this PluginLoader as it is of the wrong type!");
		}
		if (paramPlugin.isEnabled()) {
			CommonPlugin cp = (CommonPlugin) paramPlugin;
			String name = cp.getDescription().getName();

			if (!this.loaders.containsKey(name)) {
				this.loaders.put(name, (CommonClassLoader) cp.getClassLoader());
			}

			try {
				cp.setEnabled(false);
				cp.onDisable();
			} catch (Throwable t) {
				this.engine.getLogger().log(Level.SEVERE, "An error occurred when disabling plugin '" + paramPlugin.getDescription().getFullName() + "' : " + t.getMessage(), t);
			}

			this.engine.getEventManager().callEvent(new PluginDisableEvent(cp));
		}
	}

	@Override
	public synchronized Plugin loadPlugin(File paramFile) throws InvalidPluginException, UnknownDependencyException, InvalidDescriptionFileException, InsufficientClearancesException {
		return loadPlugin(paramFile, false);
	}

	@Override
	public synchronized Plugin loadPlugin(File paramFile, boolean ignoresoftdepends) throws InvalidPluginException, UnknownDependencyException, InvalidDescriptionFileException,
			InsufficientClearancesException {
		CommonPlugin result;
		PluginDescriptionFile desc;
		CommonClassLoader loader;

		desc = getDescription(paramFile);

		File dataFolder = new File(paramFile.getParentFile(), desc.getName());

		Policy policy = Policy.getPolicy();
		if (policy != null && policy instanceof CommonPolicy) {
			((CommonPolicy) policy).checkPluginLoad(desc, dataFolder);
		}

		processDependencies(desc);

		if (!ignoresoftdepends) {
			processSoftDependencies(desc);
		}

		try {
			if (this.engine.getPlatform() == Platform.CLIENT) {
				loader = new ClientClassLoader(this, this.getClass().getClassLoader(), desc.getDepends(), desc.getSoftDepends());
			} else {
				loader = new CommonClassLoader(this, this.getClass().getClassLoader(), desc.getDepends(), desc.getSoftDepends());
			}
			loader.addURL(paramFile.toURI().toURL());
			Class<?> main = Class.forName(desc.getMain(), true, loader);
			Class<? extends CommonPlugin> plugin = main.asSubclass(CommonPlugin.class);

			Constructor<? extends CommonPlugin> constructor = plugin.getConstructor();

			result = constructor.newInstance();

			result.initialize(this, this.engine, desc, dataFolder, paramFile, loader);

		} catch (Exception e) {
			throw new InvalidPluginException(e);
		} catch (UnsupportedClassVersionError e) {
			String version = e.getMessage().replaceFirst("Unsupported major.minor version ", "").split(" ")[0];
			Spout.getLogger().severe("Plugin " + desc.getName() + " is built for a newer Java version than your current installation, and cannot be loaded!");
			Spout.getLogger().severe("To run " + desc.getName() + ", you need Java version " + version + " or higher!");
			throw new InvalidPluginException(e);
		}

		loader.setPlugin(result);
		this.loaders.put(desc.getName(), loader);

		return result;
	}

	/**
	 * @param description Plugin description element
	 * @throws UnknownSoftDependencyException
	 */
	protected synchronized void processSoftDependencies(PluginDescriptionFile description) throws UnknownSoftDependencyException {
		List<String> softdepend = description.getSoftDepends();
		if (softdepend == null) {
			softdepend = new ArrayList<String>();
		}

		for (String depend : softdepend) {
			if (this.loaders == null) {
				throw new UnknownSoftDependencyException(depend);
			}
			if (!this.loaders.containsKey(depend)) {
				throw new UnknownSoftDependencyException(depend);
			}
		}
	}

	/**
	 * @param desc Plugin description element
	 * @throws UnknownDependencyException
	 */
	protected synchronized void processDependencies(PluginDescriptionFile desc) throws UnknownDependencyException {
		List<String> depends = desc.getDepends();
		if (depends == null) {
			depends = new ArrayList<String>();
		}

		for (String depend : depends) {
			if (this.loaders == null) {
				throw new UnknownDependencyException(depend);
			}
			if (!this.loaders.containsKey(depend)) {
				throw new UnknownDependencyException(depend);
			}
		}
	}

	/**
	 * @param file Plugin file object
	 * @return The current plugin's description element.
	 * @throws InvalidPluginException
	 * @throws InvalidDescriptionFileException
	 */
	protected synchronized PluginDescriptionFile getDescription(File file) throws InvalidPluginException, InvalidDescriptionFileException {
		if (!file.exists()) {
			throw new InvalidPluginException(file.getName() + " does not exist!");
		}

		PluginDescriptionFile description = null;
		JarFile jar = null;
		InputStream in = null;
		try {
			// Spout plugin properties file
			jar = new JarFile(file);
			JarEntry entry = jar.getJarEntry(YAML_SPOUT);

			// Fallback plugin properties file
			if (entry == null) {
				entry = jar.getJarEntry(YAML_OTHER);
			}

			if (entry == null) {
				throw new InvalidPluginException("Jar has no properties.yml or plugin.yml!");
			}

			in = jar.getInputStream(entry);
			description = new PluginDescriptionFile(in);
		} catch (IOException e) {
			throw new InvalidPluginException(e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					this.engine.getLogger().log(Level.WARNING, "Problem closing input stream", e);
				}
			}
			if (jar != null) {
				try {
					jar.close();
				} catch (IOException e) {
					this.engine.getLogger().log(Level.WARNING, "Problem closing jar input stream", e);
				}
			}
		}
		return description;
	}

	protected Class<?> getClassByName(final String name, final CommonClassLoader commonLoader) {
		Set<String> ignore = new HashSet<String>();

		for (String dependency : commonLoader.getDepends()) {
			try {
				Class<?> clazz = this.loaders.get(dependency).findClass(name, false);
				if (clazz != null) {
					return clazz;
				}
			} catch (ClassNotFoundException ignored) {
			}
			ignore.add(dependency);
		}

		for (String softDependency : commonLoader.getSoftDepends()) {
			try {
				Class<?> clazz = this.loaders.get(softDependency).findClass(name, false);
				if (clazz != null) {
					return clazz;
				}
			} catch (ClassNotFoundException ignored) {
			}
			ignore.add(softDependency);
		}

		for (String current : this.loaders.keySet()) {
			if (ignore.contains(current)) {
				continue;
			}
			CommonClassLoader loader = this.loaders.get(current);
			if (loader == commonLoader) {
				continue;
			}
			try {
				Class<?> clazz = loader.findClass(name, false);
				if (clazz != null) {
					return clazz;
				}
			} catch (ClassNotFoundException ignored) {
			}
		}
		return null;
	}
}
