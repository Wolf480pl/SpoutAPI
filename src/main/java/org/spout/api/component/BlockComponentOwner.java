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
package org.spout.api.component;

import org.spout.api.datatable.ManagedHashMap;
import org.spout.api.geo.World;
import org.spout.api.geo.cuboid.Block;
import org.spout.api.geo.cuboid.Chunk;

// TODO: I don't see why we shouldn't move this to Spout
public class BlockComponentOwner extends BaseComponentOwner {
	/**
	 * Stored as world, not chunk, coords
	 */
	private final int x, y, z;
	private final World world;

	public BlockComponentOwner(ManagedHashMap chunkData, int x, int y, int z, World world) {
		super(new ManagedHashMap(chunkData, "" + (x & Chunk.BLOCKS.MASK) + ","  + (y & Chunk.BLOCKS.MASK) + ","  + (z & Chunk.BLOCKS.MASK)));
		this.x = x;
		this.y = y;
		this.z = z;
		this.world = world;
	}

	public Block getBlock() {
		return world.getBlock(x, y, z);
	}

	public int getX() {
		return x;
	}

	public int getY() {
		return y;
	}

	public int getZ() {
		return z;
	}

	public World getWorld() {
		return world;
	}
}
