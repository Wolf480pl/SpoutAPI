/*
 * This file is part of SpoutAPI (http://www.spout.org/).
 *
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
package org.spout.api.inventory;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class Inventory implements Serializable {

	private static final long serialVersionUID = 0L;
	private final ItemStack[] contents;
	private Set<Integer> hidden = new HashSet<Integer>();
	private int currentSlot;
	private boolean dirty = false;

	public Inventory(int size) {
		contents = new ItemStack[size];
		currentSlot = 0;
	}

	public boolean isDirty() {
		return dirty;
	}

	public void setDirty(boolean newVal) {
		dirty = newVal;
	}

	public void setHiddenSlot(int slot, boolean newValue) {
		if (newValue) {
			hidden.add(slot);
		} else {
			hidden.remove(slot);
		}
	}

	public boolean isHiddenSlot(int slot) {
		return hidden.contains(slot);
	}

	public ItemStack[] getContents() {
		return contents;
	}

	public ItemStack getItem(int slot) {
		return contents[slot];
	}

	public void setItem(ItemStack item, int slot) {
		contents[slot] = item;
		setDirty(true);
	}

	public boolean addItem(ItemStack item) {
		for (int i = 0; i < contents.length; i++) {
			if (hidden.contains(i)) continue;
			if (contents[i] != null && contents[i].getMaterial() == item.getMaterial()) {
				int canTake = (contents[i].getMaterial().getMaxStackSize() - contents[i].getAmount());
				if (canTake >= item.getAmount()) {
					contents[i].setAmount(contents[i].getAmount() + item.getAmount());
					setDirty(true);
					return true;
				} else {
					item.setAmount(item.getAmount() - canTake);
					contents[i].setAmount(contents[i].getMaterial().getMaxStackSize());
				}
			}
		}

		for (int i = 0; i < contents.length; i++) {
			if (hidden.contains(i)) continue;
			if (contents[i] == null) {
				contents[i] = item;
				setDirty(true);
				return true;
			}
		}
		return false;
	}

	public int getSize() {
		return contents.length;
	}

	public ItemStack getCurrentItem() {
		return getItem(currentSlot);
	}

	public int getCurrentSlot() {
		return currentSlot;
	}

	public void setCurrentSlot(int slot) {
		if (slot < 0 || slot >= contents.length) {
			throw new ArrayIndexOutOfBoundsException();
		}
		currentSlot = slot;
		setDirty(true);
	}
}
