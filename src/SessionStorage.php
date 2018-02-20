<?php
/**
 * MIT License
 *
 * Copyright (c) 2018 Pentagonal Development
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace Apatis\Auth\Easy;

/**
 * Class SessionStorage
 * @package Apatis\Generator\Easy
 */
class SessionStorage implements \Serializable, \JsonSerializable, \ArrayAccess
{
    /**
     * @var array
     */
    protected $sessions = [];

    /**
     * SessionStorage constructor.
     *
     * @param array $sessions
     */
    public function __construct(array $sessions = [])
    {
        $this->sessions = $sessions;
    }

    /**
     * @param string $name
     * @param null $default
     *
     * @return mixed|null
     */
    public function get($name, $default = null)
    {
        if (!is_string($name) && !is_numeric($name)) {
            return $default;
        }

        return array_key_exists($name, $this->sessions)
            ? $this->sessions[$name]
            : $default;
    }

    /**
     * @param $name
     *
     * @return bool
     */
    public function has($name) : bool
    {
        if (!is_string($name) && !is_numeric($name)) {
            return false;
        }

        return array_key_exists($name, $this->sessions);
    }

    /**
     * Set SessionStorage Value
     *
     * @param string $name
     * @param mixed $value
     */
    public function set($name, $value)
    {
        $this->sessions[$name] = $value;
    }

    /**
     * Remove SessionStorage
     *
     * @param string $name
     */
    public function remove($name)
    {
        if (!is_string($name) && !is_numeric($name)) {
            return;
        }

        if (array_key_exists($name, $this->sessions)) {
            unset($this->sessions[$name]);
        }
    }

    /**
     * @return bool
     */
    public function isEmpty() : bool
    {
        return count($this->sessions) === 0;
    }

    /**
     * @return array
     */
    public function toArray() : array
    {
        return $this->sessions;
    }

    /**
     * Magic Method Serialize
     *
     * {@inheritdoc}
     *
     * @return string
     */
    public function serialize() : string
    {
        return serialize($this->toArray());
    }

    /**
     * Magic Method Unserialize
     *
     * {@inheritdoc}
     * @param string $serialized
     */
    public function unserialize($serialized)
    {
        if (!is_string($serialized)) {
            return;
        }

        set_error_handler(function () {
            error_clear_last();
        });
        $unSerialized = unserialize($serialized);
        restore_error_handler();
        if (is_array($unSerialized)) {
            $this->sessions = $unSerialized;
        }
    }

    /**
     * Magic Method Json Serializable
     * {@inheritdoc}
     *
     * @return array
     */
    public function jsonSerialize() : array
    {
        return $this->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        return $this->has($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        return $this->get($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $value)
    {
        $this->set($offset, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        $this->remove($offset);
    }
}
