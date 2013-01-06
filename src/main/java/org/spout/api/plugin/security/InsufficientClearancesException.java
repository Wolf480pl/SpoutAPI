package org.spout.api.plugin.security;


public class InsufficientClearancesException extends Exception {
	private static final long serialVersionUID = 2130588298827844380L;

	public InsufficientClearancesException() {
		super("Not all clearances required by plugin are granted.");
	}

	public InsufficientClearancesException(String msg) {
		super(msg);
	}

}
