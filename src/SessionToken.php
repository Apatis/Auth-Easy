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
 * Class SessionToken
 * @package Apatis\Generator\Easy
 */
class SessionToken implements \Serializable, \JsonSerializable
{
    const EXPIRATION_NAME = 'expiration';
    const IP_ADDRESS_NAME = 'ip';
    const USER_AGENT_NAME = 'user_agent';
    const LOGIN_TIME_NAME = 'login';
    const TOKEN_LENGTH = 43;

    /**
     * @var SessionStorage[]
     */
    protected $sessions = [];

    /**
     * SessionToken constructor.
     * @param array $sessions
     */
    public function __construct(array $sessions = [])
    {
        $this->sessions = $this->prepareReadySessions($sessions);
    }

    /**
     * Get Expiration Name
     *
     * @return string
     */
    public function getExpirationName() : string
    {
        return static::EXPIRATION_NAME;
    }

    /**
     * @param array|mixed $sessions
     *
     * @return array|SessionStorage[]
     */
    protected function prepareReadySessions($sessions) : array
    {
        /**
         * if is not array convert into empty array
         */
        if (!is_array($sessions)) {
            return [];
        }

        foreach ($sessions as $key => $sessionValue) {
            if (!is_string($key)) {
                unset($sessions[$key]);
                continue;
            }

            if (is_array($sessionValue)) {
                $sessionValue = new SessionStorage($sessionValue);
            } elseif (! $sessionValue instanceof SessionStorage) {
                unset($sessions[$key]);
                continue;
            }

            $sessionValue = $this->sessionsPrepare($sessionValue);
            if (! $this->isNotExpired($sessionValue)) {
                unset($sessions[$key]);
                continue;
            }

            $sessions[$key] = $sessionValue;
        }

        return $sessions;
    }

    /**
     * @param int|array $session
     *
     * @return SessionStorage
     */
    protected function sessionsPrepare($session) : SessionStorage
    {
        if (!is_array($session) && ! $session instanceof SessionStorage) {
            $session = [];
        }

        if (is_array($session)) {
            return new SessionStorage($session);
        }

        return $session;
    }

    /**
     * Update a user's sessions in the user meta table.
     *
     * @param array $sessions Sessions.
     */
    protected function updateSessions(array $sessions)
    {
        $this->sessions = $this->prepareReadySessions($sessions);
    }

    /**
     * Get All Sessions
     *
     * @return array
     */
    public function getSessions() : array
    {
        return $this->sessions = $this->prepareReadySessions($this->sessions);
    }

    /**
     * @param string $verifier
     *
     * @return bool
     */
    public function hasSession(string $verifier) : bool
    {
        $session = $this->getSessions();
        return isset($session[$verifier]) && is_array($session[$verifier]);
    }

    /**
     * Retrieve a session by its verifier (token hash).
     *
     * @param string $verifier
     *
     * @return SessionStorage|null
     */
    public function getSession(string $verifier)
    {
        $sessions = $this->getSessions();
        if (isset($sessions[$verifier]) && $sessions[$verifier] instanceof SessionStorage) {
            return $sessions[$verifier];
        }

        return null;
    }

    /**
     * Determine whether a session token is still valid,
     * based on expiration.
     *
     * @param SessionStorage $session
     *
     * @return bool
     */
    public function isNotExpired(SessionStorage $session) : bool
    {
        $expiration = $session->get($this->getExpirationName());
        return is_numeric($expiration) && $expiration >= $this->getCurrentTime();
    }

    /**
     * Update a session by its verifier.
     *
     * @param string $verifier Verifier of the session to update.
     * @param SessionStorage $session Optional. SessionStorage. Omitting this argument destroys the session.
     */
    public function updateSession($verifier, SessionStorage $session = null)
    {
        $sessions = $this->getSessions();
        if ($session === null) {
            unset($sessions[$verifier]);
        } else {
            $sessions[$verifier] = $session;
        }

        $this->updateSessions($sessions);
    }

    /**
     * Add additional Info
     *
     * @param array $sessions
     *
     * @return array
     */
    protected function generateAdditionalInfo(array $sessions): array
    {
        return $sessions;
    }

    /**
     * Hash The Token
     *
     * @param string $token
     *
     * @return string
     */
    public static function hash(string $token) : string
    {
        return hash('sha256', $token);
    }

    /**
     * Get Current Time integer use time() for normal operation
     *
     * @return int
     */
    public function getCurrentTime() : int
    {
        return time();
    }

    /**
     * @param array $session
     *
     * @return array
     */
    public function generateSessionFromArray(array $session) : array
    {
        // IP address.
        if (isset($_SERVER['REMOTE_ADDR'])) {
            $session[static::IP_ADDRESS_NAME] = $_SERVER['REMOTE_ADDR'];
        }

        // User-agent.
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $session[static::USER_AGENT_NAME] = $_SERVER['HTTP_USER_AGENT'];
        }

        // Timestamp
        $session[static::LOGIN_TIME_NAME] = $this->getCurrentTime();
        return $session;
    }

    /**
     * Check if session exists & valid by token
     *
     * @param string $token
     *
     * @return bool
     */
    final public function has(string $token) : bool
    {
        $verifier = $this->hash($token);
        return $this->hasSession($verifier);
    }

    /**
     * Get Session By Token
     *
     * @param string $token
     *
     * @return SessionStorage|null
     */
    final public function get(string $token)
    {
        $verifier = $this->hash($token);
        return $this->getSession($verifier);
    }

    /**
     * Update a session token.
     *
     * @param string $token SessionStorage token to update.
     * @param array|SessionStorage $session SessionStorage information.
     */
    final public function update(string $token, $session)
    {
        if (is_array($session)) {
            $session = new SessionStorage($session);
        }
        if (!$session instanceof SessionStorage) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Update session must be array or instance of %s. %s given',
                    SessionStorage::class,
                    gettype($session)
                )
            );
        }

        $this->updateSession($this->hash($token), $session);
    }

    /**
     * Generate a session token and attach session information to it.
     *
     * A session token is a long, UUID v4 string. It is used in a cookie
     * link that cookie to an expiration time and to ensure the cookie
     * becomes invalidated upon logout.
     *
     * @param int $expiration SessionStorage expiration timestamp.
     *
     * @return string SessionStorage token.
     */
    final public function create(int $expiration) : string
    {
        $session   = [$this->getExpirationName() => $expiration];
        $token     = Generator::generateUUIDv4();
        $session   = array_merge(
            $this->generateAdditionalInfo($session),
            $this->generateSessionFromArray($session)
        );
        $this->update($token, $session);
        return $token;
    }

    /**
     * Destroy a session token.
     *
     * @param string $token SessionStorage token to destroy.
     */
    final public function remove(string $token)
    {
        $this->updateSession($this->hash($token));
    }

    /**
     * Destroy all session token.
     */
    final public function deleteAll()
    {
        $this->sessions = [];
    }

    /**
     * @param string $token
     *
     * @return bool
     */
    final public function removeOthers(string $token) : bool
    {
        $verifier = $this->hash($token);
        $session = $this->getSession($verifier);
        if (!empty($session) && $session instanceof SessionStorage) {
            $this->sessions = [];
            $this->updateSession($verifier, $session);
            return true;
        }

        return false;
    }

    /**
     * Verify Token
     *
     * @param string $token
     *
     * @return bool
     */
    final public function verify(string $token) : bool
    {
        $session = $this->getSession($this->hash($token));
        return $session instanceof SessionStorage;
    }

    /**
     * @return array
     */
    public function toArray() : array
    {
        return $this->getSessions();
    }

    /**
     * @return string
     */
    public function serialize()
    {
        return serialize($this->toArray());
    }

    /**
     * Magic Method Un-Serialize
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
            $this->updateSessions($unSerialized);
        }
    }

    /**
     * {@inheritdoc}
     *
     * @return array
     */
    public function jsonSerialize() : array
    {
        return $this->toArray();
    }
}
