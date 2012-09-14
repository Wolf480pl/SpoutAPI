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
package org.spout.api.component.components;

import org.spout.api.component.Component;
import org.spout.api.geo.discrete.Point;
import org.spout.api.geo.discrete.Transform;
import org.spout.api.math.Quaternion;
import org.spout.api.math.Vector3;

public interface TransformComponent extends Component {

	public void setTransform(Transform transform);

	public Transform getTransform();

	public Transform getTransformLive();

	public boolean isDirty();

	public Point getPosition();

	public void setPosition(Point position);

	public Quaternion getRotation();

	public void setRotation(Quaternion rotation);

	public Vector3 getScale();

	public void setScale(Vector3 scale);

	/**
	 * Moves the entity by the provided vector<br/>
	 * @param amount to move the entity
	 */
	public void translate(Vector3 amount);

	/**
	 * Moves the entity by the provided vector
	 * @param x offset
	 * @param y offset
	 * @param z offset
	 */
	public void translate(float x, float y, float z);

	/**
	 * Rotates the entity about the provided axis by the provided angle
	 * @param ang
	 * @param x
	 * @param y
	 * @param z
	 */
	public void rotate(float w, float x, float y, float z);
	/**
	 * Rotates the entity by the provided rotation
	 * @param rot
	 */
	public void rotate(Quaternion rot);

	/**
	 * Scales the entity by the provided amount
	 * @param amount
	 */
	public void scale(Vector3 amount);

	/**
	 * Scales the entity by the provided amount
	 * @param x
	 * @param y
	 * @param z
	 */
	public void scale(float x, float y, float z);

	/**
	 * Pitches the entity by the provided amount
	 * @param angle
	 */
	public void pitch(float angle);

	/**
	 * Yaws the entity by the provided amount
	 * @param angle
	 */
	public void yaw(float angle);

	/**
	 * Rolls the entity by the provided amount
	 * @param angle
	 */
	public void roll(float angle);

	/**
	 * Gets the entities current pitch, or vertical angle.
	 * @return pitch of the entity
	 */
	public float getPitch();

	/**
	 * Gets the entities current yaw, or horizontal angle.
	 * @return yaw of the entity.
	 */
	public float getYaw();

	/**
	 * Gets the entities current roll as a float.
	 * @return roll of the entity
	 */
	public float getRoll();

	/**
	 * Sets the pitch of the entity.
	 * @param ang
	 */
	public void setPitch(float angle);
	/**
	 * Sets the roll of the entity.
	 * @param ang
	 */
	public void setRoll(float angle);

	/**
	 * sets the yaw of the entity.
	 * @param ang
	 */
	public void setYaw(float angle);
}
