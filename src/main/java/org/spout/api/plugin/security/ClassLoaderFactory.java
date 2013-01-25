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

import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class ClassLoaderFactory {
	private static final HelperSecurityManager helper = new HelperSecurityManager();
	private final ClassLoader parent;

	private ClassLoaderFactory(ClassLoader parent) {
		this.parent = parent;
	}

	public URLClassLoader createClassLoader(final URL[] urls) {
		return AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>() {
			@Override
			public URLClassLoader run() {
				return new URLClassLoader(urls, parent);
			}
		});
	}

	public static ClassLoaderFactory getInstance() {
		ClassLoader parent = helper.getCallerClass(2).getClassLoader();
		if (parent != null) {
			return new ClassLoaderFactory(parent);
		}
		return null;
	}

	private static final class HelperSecurityManager extends SecurityManager {
		public Class<?> getCallerClass(int depth) {
			return getClassContext()[depth];
		}

	}

}