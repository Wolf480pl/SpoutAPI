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
import java.util.List;

import org.spout.api.exception.InvalidDescriptionFileException;
import org.spout.api.exception.InvalidPluginException;
import org.spout.api.exception.UnknownDependencyException;
import org.spout.api.plugin.security.InsufficientClearancesException;

public interface PluginManager {
	/**
	 * Returns the the instance of a plugins when given its name
	 * @param plugin's name
	 * @return instance of the plugin
	 */
	public abstract Plugin getPlugin(String plugin);

	/**
	 * Returns an array of plugins that have been loaded
	 * @return plugins
	 */
	public List<Plugin> getPlugins();

	/**
	 * Loads the file as a plugin
	 * @param file
	 * @return instance of the plugin
	 * @throws InvalidPluginException
	 * @throws InvalidDescriptionFileException
	 * @throws UnknownDependencyException
	 * @throws InsufficientClearancesException
	 */
	public abstract Plugin loadPlugin(File file) throws InvalidPluginException, InvalidDescriptionFileException, UnknownDependencyException, InsufficientClearancesException;

	/**
	 * Loads all plugins in a directory
	 * @param file
	 * @return array of plugins loaded
	 */
	public abstract List<Plugin> loadPlugins(File file);

	/**
	 * Disables all plugins
	 */
	public abstract void disablePlugins();

	/**
	 * Disables all plugins and clears the List of plugins
	 */
	public abstract void clearPlugins();

	/**
	 * Enables the plugin
	 * @param plugin
	 */
	public abstract void enablePlugin(Plugin plugin);

	/**
	 * Disables the plugin
	 * @param plugin
	 */
	public abstract void disablePlugin(Plugin plugin);
}
