/*
 * This file is part of SpoutAPI.
 *
 * Copyright (c) 2011-2012, SpoutDev <http://www.spout.org/>
 * SpoutAPI is licensed under the SpoutDev License Version 1.
 *
 * SpoutAPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * In addition, 180 days after any changes are published, you can use the
 * software, incorporating those changes, under the terms of the MIT license,
 * as described in the SpoutDev License Version 1.
 *
 * SpoutAPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License,
 * the MIT license and the SpoutDev License Version 1 along with this program.
 * If not, see <http://www.gnu.org/licenses/> for the GNU Lesser General Public
 * License and see <http://www.spout.org/SpoutDevLicenseV1.txt> for the full license,
 * including the MIT license.
 */
package org.spout.api.plugin;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;

import org.spout.api.Engine;
import org.spout.api.event.HandlerList;
import org.spout.api.exception.InvalidDescriptionFileException;
import org.spout.api.exception.InvalidPluginException;
import org.spout.api.exception.UnknownDependencyException;
import org.spout.api.meta.SpoutMetaPlugin;

public class CommonPluginManager implements PluginManager {
	private final Engine engine;
	private final SpoutMetaPlugin metaPlugin;
	private final Map<Pattern, PluginLoader> loaders = new HashMap<Pattern, PluginLoader>();
	private final Map<String, Plugin> names = new HashMap<String, Plugin>();
	private final List<Plugin> plugins = new ArrayList<Plugin>();
	private File updateDir;

	public CommonPluginManager(final Engine engine) {
		this.engine = engine;
		this.metaPlugin = new SpoutMetaPlugin(engine);
	}

	public void registerPluginLoader(Class<? extends PluginLoader> loader) {
		PluginLoader instance = null;
		try {
			Constructor<? extends PluginLoader> constructor = loader.getConstructor(new Class[]{Engine.class});

			instance = constructor.newInstance(this.engine);
		} catch (Exception e) {
			throw new IllegalArgumentException("Error registering plugin loader!", e);
		}

		synchronized (this) {
			for (Pattern pattern : instance.getPatterns()) {
				this.loaders.put(pattern, instance);
			}
		}
	}

	@Override
	public Plugin getPlugin(String plugin) {
		return this.names.get(plugin);
	}

	@Override
	public List<Plugin> getPlugins() {
		return Collections.unmodifiableList(this.plugins);
	}

	@Override
	public synchronized Plugin loadPlugin(File paramFile) throws InvalidPluginException, InvalidDescriptionFileException, UnknownDependencyException {
		return loadPlugin(paramFile, false);
	}

	public synchronized Plugin loadPlugin(File paramFile, boolean ignoreSoftDependencies) throws InvalidPluginException, InvalidDescriptionFileException, UnknownDependencyException {
		File update = null;

		if (this.updateDir != null && this.updateDir.isDirectory()) {
			update = new File(this.updateDir, paramFile.getName());
			if (update.exists() && update.isFile()) {
				try {
					FileUtils.copyFile(update, paramFile);
				} catch (IOException e) {
					safelyLog(Level.SEVERE, new StringBuilder().append("Error copying file '").append(update.getPath()).append("' to its new destination at '").append(paramFile.getPath()).append("': ").append(e.getMessage()).toString(), e);
				}
				update.delete();
			}
		}

		Set<Pattern> patterns = this.loaders.keySet();
		Plugin result = null;

		for (Pattern pattern : patterns) {
			String name = paramFile.getName();
			Matcher m = pattern.matcher(name);

			if (m.find()) {
				PluginLoader loader = this.loaders.get(pattern);
				result = loader.loadPlugin(paramFile, ignoreSoftDependencies);

				if (result != null) {
					break;
				}
			}
		}

		if (result != null) {
			this.plugins.add(result);
			this.names.put(result.getDescription().getName(), result);
		}
		return result;
	}

	@Override
	public synchronized List<Plugin> loadPlugins(File paramFile) {
		if (!paramFile.isDirectory()) {
			throw new IllegalArgumentException("File parameter was not a Directory!");
		}

		if (this.engine.getUpdateFolder() != null) {
			this.updateDir = this.engine.getUpdateFolder();
		}

		loadMetaPlugin();

		List<Plugin> result = new ArrayList<Plugin>();
		LinkedList<File> files = new LinkedList<File>(Arrays.asList(paramFile.listFiles()));
		boolean failed = false;
		boolean lastPass = false;

		while (!failed || lastPass) {
			failed = true;
			Iterator<File> iterator = files.iterator();

			while (iterator.hasNext()) {
				File file = iterator.next();
				Plugin plugin = null;

				if (file.isDirectory()) {
					iterator.remove();
					continue;
				}

				try {
					plugin = loadPlugin(file, lastPass);
					iterator.remove();
				} catch (UnknownDependencyException e) {
					if (lastPass) {
						safelyLog(Level.SEVERE, new StringBuilder().append("Unable to load '").append(file.getName()).append("' in directory '").append(paramFile.getPath()).append("': ").append(e.getMessage()).toString(), e);
						iterator.remove();
					}
				} catch (InvalidDescriptionFileException e) {
					safelyLog(Level.SEVERE, new StringBuilder().append("Unable to load '").append(file.getName()).append("' in directory '").append(paramFile.getPath()).append("': ").append(e.getMessage()).toString(), e);
					iterator.remove();
				} catch (InvalidPluginException e) {
					safelyLog(Level.SEVERE, new StringBuilder().append("Unable to load '").append(file.getName()).append("' in directory '").append(paramFile.getPath()).append("': ").append(e.getMessage()).toString(), e);
					iterator.remove();
				}

				if (plugin != null) {
					result.add(plugin);
					failed = false;
					lastPass = false;
				}
			}
			if (lastPass) {
				break;
			} else if (failed) {
				lastPass = true;
			}
		}

		return Collections.unmodifiableList(result);
	}

	@Override
	public void disablePlugins() {
		for (Plugin plugin : this.plugins) {
			if (plugin == this.metaPlugin) {
				continue;
			}
			disablePlugin(plugin);
		}
	}

	@Override
	public void clearPlugins() {
		synchronized (this) {
			disablePlugins();
			this.plugins.clear();
			this.names.clear();
		}
	}

	@Override
	public void enablePlugin(Plugin plugin) {
		if (plugin == this.metaPlugin) {
			return;
		}
		if (!plugin.isEnabled()) {
			try {
				plugin.getPluginLoader().enablePlugin(plugin);
			} catch (Exception e) {
				safelyLog(Level.SEVERE, "An error occurred in the Plugin Loader while enabling plugin '" + plugin.getDescription().getFullName() + "': " + e.getMessage(), e);
			}
		}
	}

	@Override
	public void disablePlugin(Plugin plugin) {
		if (plugin == this.metaPlugin) {
			return;
		}
		if (plugin.isEnabled()) {
			try {
				plugin.getPluginLoader().disablePlugin(plugin);
				HandlerList.unregisterAll(plugin);
				this.engine.getServiceManager().unregisterAll(plugin);
				this.engine.getRootCommand().removeChildren(plugin);
			} catch (Exception e) {
				safelyLog(Level.SEVERE, "An error occurred in the Plugin Loader while disabling plugin '" + plugin.getDescription().getFullName() + "': " + e.getMessage(), e);
			}
		}
	}

	private void safelyLog(Level level, String message, Throwable ex) {
		// This was meant to log the message with engine privileges.
		this.engine.getLogger().log(level, message, ex);
	}

	public void loadMetaPlugin() {
		this.plugins.add(this.metaPlugin);
		this.names.put("Spout", this.metaPlugin);
	}

	public SpoutMetaPlugin getMetaPlugin() {
		return this.metaPlugin;
	}
}
