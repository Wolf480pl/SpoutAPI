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
package org.spout.api.util.config;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;

import org.spout.api.exception.ConfigurationException;
import org.spout.api.util.ReflectionUtils;

/**
 * This is a configuration holder class that takes another Configuration and wraps some
 * reflection to get all the fields in the subclass that have values of the type {@link ConfigurationHolder}.
 * These fields will be automatically associated with the attached configuration and have
 * their default values loaded into the configuration as needed on load
 */
public abstract class ConfigurationHolderConfiguration extends ConfigurationWrapper  {
	private final List<Field> holders = new ArrayList<Field>();

	public ConfigurationHolderConfiguration(Configuration base) {
		super(base);
		for (final Field field : ReflectionUtils.getDeclaredFieldsRecur(getClass())) {
			AccessController.doPrivileged(new PrivilegedAction() {
				@Override
				public Object run() {
					field.setAccessible(true);
					return null;
				}
			});

			if (ConfigurationHolder.class.isAssignableFrom(field.getType())) {
				holders.add(field);
			}
		}
	}

	@Override
	public void load() throws ConfigurationException {
		super.load();
		for (Field field : this.holders) {
			try {
				ConfigurationHolder holder = (ConfigurationHolder) field.get(this);
				if (holder != null) {
					holder.setConfiguration(getConfiguration());
					holder.getValue(); // Initialize the ConfigurationHolder's value
				}
			} catch (IllegalAccessException e) {
			}
		}
	}
}
