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