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

import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.spout.api.exception.ConfigurationException;
import org.spout.api.exception.InvalidDescriptionFileException;
import org.spout.api.util.config.ConfigurationNode;
import org.spout.api.util.config.ConfigurationNodeSource;
import org.spout.api.util.config.serialization.Serialization;
import org.spout.api.util.config.yaml.YamlConfiguration;

public class PluginDescriptionFile {
	public static final List<String> RESTRICTED_NAMES = Collections.unmodifiableList(Arrays.asList(
			"org.spout",
			"org.getspout",
			"org.spoutcraft",
			"in.spout"));
	private final HashMap<String, String> data = new HashMap<String, String>();
	private String name;
	private String version;
	private String description;
	private List<String> authors = new ArrayList<String>();
	private String website;
	private boolean reload;
	private Platform platform;
	private LoadOrder load;
	private String main;
	private List<String> depends;
	private List<String> softdepends;
	private String fullname;
	private Locale codedLocale = Locale.ENGLISH;
	private ConfigurationNode requiredClearances;
	private ConfigurationNode optionalClearances;

	public PluginDescriptionFile(String name, String version, String main, Platform platform) {
		this.name = name;
		this.version = version;
		this.main = main;
		this.platform = platform;
		fullname = name + " v" + version;
	}

	public PluginDescriptionFile(InputStream stream) throws InvalidDescriptionFileException {
		YamlConfiguration yaml = new YamlConfiguration(stream);
		try {
			yaml.load();
		} catch (ConfigurationException e) {
			throw new InvalidDescriptionFileException(e);
		}
		load(yaml);
	}

	public PluginDescriptionFile(Reader reader) throws InvalidDescriptionFileException {
		YamlConfiguration yaml = new YamlConfiguration(reader);
		try {
			yaml.load();
		} catch (ConfigurationException e) {
			throw new InvalidDescriptionFileException(e);
		}
		load(yaml);
	}

	public PluginDescriptionFile(String raw) throws InvalidDescriptionFileException {
		YamlConfiguration yaml = new YamlConfiguration(raw);
		try {
			yaml.load();
		} catch (ConfigurationException e) {
			throw new InvalidDescriptionFileException(e);
		}
		load(yaml);
	}

	private void load(YamlConfiguration yaml) throws InvalidDescriptionFileException {
		name = getEntry("name", String.class, yaml);
		if (!name.matches("^[A-Za-z0-9 _.-]+$")) {
			throw new InvalidDescriptionFileException("The field 'name' in properties.yml contains invalid characters.");
		}
		if (name.toLowerCase().contains("spout")) {
			throw new InvalidDescriptionFileException("The plugin '" + name + "' has Spout in the name. This is not allowed.");
		}

		main = getEntry("main", String.class, yaml);
		if (!isOfficialPlugin(main)) {
			for (String namespace : RESTRICTED_NAMES) {
				if (main.startsWith(namespace)) {
					throw new InvalidDescriptionFileException("The use of the namespace '" + namespace + "' is not permitted.");
				}
			}
		}

		version = getEntry("version", String.class, yaml);
		platform = getEntry("platform", Platform.class, yaml);
		fullname = name + " v" + version;

		if (yaml.hasChild("author")) {
			authors.add(getEntry("author", String.class, yaml));
		}

		if (yaml.hasChild("authors")) {
			authors.addAll(getEntry("authors", List.class, yaml));
		}

		if (yaml.hasChild("depends")) {
			depends = getEntry("depends", List.class, yaml);
		}

		if (yaml.hasChild("softdepends")) {
			softdepends = getEntry("softdepends", List.class, yaml);
		}

		if (yaml.hasChild("description")) {
			description = getEntry("description", String.class, yaml);
		}

		if (yaml.hasChild("load")) {
			load = getEntry("load", LoadOrder.class, yaml);
		}

		if (yaml.hasChild("reload")) {
			reload = getEntry("reload", Boolean.class, yaml);
		}

		if (yaml.hasChild("website")) {
			website = getEntry("website", String.class, yaml);
		}

		if (yaml.hasChild("codedlocale")) {
			Locale[] locales = Locale.getAvailableLocales();
			for (Locale l : locales) {
				if (l.getLanguage().equals((new Locale(yaml.getChild("codedlocale").getString())).getLanguage())) {
					codedLocale = l;
				}
			}
		}
		if (yaml.hasChild("data")) {
			Map<String, ConfigurationNode> data = yaml.getChild("data").getChildren();
			for (Map.Entry<String, ConfigurationNode> entry : data.entrySet()) {
				String key = entry.getKey();
				String value = entry.getValue().getString();
				this.data.put(key, value);
			}
		}

		if (yaml.hasChild("clearances")) {
			ConfigurationNode clearances = yaml.getChild("clearances");
			if (clearances.hasChild("required")) {
				requiredClearances = clearances.getChild("required");
			}
			if (clearances.hasChild("optional")) {
				optionalClearances = clearances.getChild("optional");
			}
		}
	}

	@SuppressWarnings("unchecked")
	private <T> T getEntry(Object key, Class<T> type, Map<?, ?> values) throws InvalidDescriptionFileException {
		Object value = values.get(key);
		if (value == null) {
			throw new InvalidDescriptionFileException("The field '" + key + "' is not present in the properties.yml!");
		}

		return (T) Serialization.deserialize(type, value);
	}

	private <T> T getEntry(String key, Class<T> type, ConfigurationNodeSource src) throws InvalidDescriptionFileException {
		T value = src.getChild(key).getTypedValue(type);
		if (value == null) {
			throw new InvalidDescriptionFileException("The field '" + key + "' is not present in the properties.yml!");
		}
		return value;
	}

	/**
	 * Returns true if the plugin is an Official Spout Plugin
	 * @param namespace The plugin's main class namespace
	 * @return true if an official plugin
	 */
	private boolean isOfficialPlugin(String namespace) {
		return (namespace.equalsIgnoreCase("org.spout.vanilla.plugin.VanillaPlugin")
				|| namespace.equalsIgnoreCase("org.spout.bridge.VanillaBridgePlugin")
				|| namespace.equalsIgnoreCase("org.spout.infobjects.InfObjectsPlugin")
				|| namespace.startsWith("org.spout.droplet"));
	}

	/**
	 * Returns the plugin's name
	 * @return name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the plugin's version
	 * @return version
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Returns the plugin's description
	 * @return description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns the plugin's authors
	 * @return authors
	 */
	public List<String> getAuthors() {
		return authors;
	}

	/**
	 * Returns the plugin's website
	 * @return website
	 */
	public String getWebsite() {
		return website;
	}

	/**
	 * Returns false if the plugin wants to be exempt from a reload
	 * @return reload
	 */
	public boolean allowsReload() {
		return reload;
	}

	/**
	 * Returns the plugin's platform
	 * @return platform
	 */
	public Platform getPlatform() {
		return platform;
	}

	/**
	 * Returns the plugin's load order
	 * @return load
	 */
	public LoadOrder getLoad() {
		return load;
	}

	/**
	 * Returns the path the plugins main class
	 * @return main
	 */
	public String getMain() {
		return main;
	}

	/**
	 * Returns the plugin's dependencies
	 * @return depends
	 */
	public List<String> getDepends() {
		return depends;
	}

	/**
	 * Returns the plugin's soft dependencies
	 * @return softdepends
	 */
	public List<String> getSoftDepends() {
		return softdepends;
	}

	/**
	 * Returns the plugin's fullname The fullname is formatted as follows:
	 * [name] v[version]
	 * @return The full name of the plugin
	 */
	public String getFullName() {
		return fullname;
	}

	/**
	 * Returns the locale the strings in the plugin are coded in.
	 * Will be read from the plugins properties.yml from the field "codedlocale"
	 * @return the locale the plugin is coded in
	 */
	public Locale getCodedLocale() {
		return codedLocale;
	}

	public String getData(String key) {
		return data.get(key);
	}

	/**
	 * Returns the clearances required for the plugin to work properly (client-side only).
	 * Will be read from the plugins properties.yml from the field "clearances: required"
	 * @return
	 */
	public ConfigurationNode getRequiredClearances() {
		return requiredClearances;
	}

	/**
	 * Returns the optional clearances, not required for the plugin to work properly (client-side only).
	 * Will be read from the plugins properties.yml from the field "clearances: optional"
	 * @return
	 */
	public ConfigurationNode getOptionalClearances() {
		return optionalClearances;
	}
}
