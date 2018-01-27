<?php
/**
 * MIT License
 *
 * Copyright (c) 2018, Pentagonal
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
 * Class Generator
 * @package Apatis\Generator\Easy
 */
class Generator
{
    const USERNAME_KEY   = 'username';
    const TOKEN_KEY      = 'token';
    const HMAC_KEY       = 'hmac';
    const EXPIRATION_KEY = 'expiration';
    const SIGN_KEY       = 'sign';

    /**
     * @var array
     */
    private static $salt = [];

    /**
     * @var string
     */
    protected $secretKey;

    /**
     * Generator constructor.
     *
     * @param string $secretKey random key for secret sessions
     */
    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * Create Salt By Secret Key
     *
     * @param string $scheme
     *
     * @return string
     */
    final protected function createSalt(string $scheme) : string
    {
        $key = sha1($this->secretKey . $scheme);
        if (isset(self::$salt[$key])) {
            return self::$salt[$key];
        }

        $salt = hash_hmac('md5', $scheme, $this->secretKey);
        return self::$salt[$key] = $this->secretKey . $salt;
    }

    /**
     * Create generated Hash
     *
     * @param string $data
     * @param string $scheme
     *
     * @return string
     */
    final protected function createHash(string $data, string $scheme) : string
    {
        $salt = $this->createSalt($scheme);
        return hash_hmac('md5', $data, $salt);
    }

    /**
     * Normalize Username for fragment
     *
     * @param string $username
     *
     * @return string
     */
    protected function fragmentUsername(string $username) : string
    {
        return $username;
    }

    /**
     * Normalize Password, this is can be extends as filtering password
     *
     * @param string $password
     *
     * @return string
     */
    public function fragmentPassword(string $password) : string
    {
        return hash_hmac('sha1', $password, $this->secretKey);
    }

    /**
     * Generate The JSON DATA Value
     *
     * @param string $userName
     * @param string $password
     * @param string $scheme
     * @param string|null $token
     * @param int $expiration
     *
     * @return string
     */
    final public function generate(
        string $userName,
        string $password,
        string $scheme,
        int $expiration = null,
        string $token = null
    ) : string {
        if (! $token) {
            $token = SessionToken::generateRandomStringToken(SessionToken::TOKEN_LENGTH);
        }
        if (!$expiration) {
            $expiration = time() + 3600;
        }
        // normalize Username
        $userName = $this->fragmentUsername($userName);
        // check password also if password does not match for next auth
        $pass_frag = $this->fragmentPassword($password);
        $key = $this->createHash($userName . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme);
        $hash = hash_hmac('sha256', $userName . '|' . $expiration . '|' . $token, $key);
        $cookie = [
            static::USERNAME_KEY   => $userName,
            static::EXPIRATION_KEY => $expiration,
            static::TOKEN_KEY      => $token,
            static::HMAC_KEY       => $hash
        ];
        $cookie[static::SIGN_KEY] = $this->sign($cookie);
        return json_encode($cookie);
    }

    /**
     * @param array $values
     *
     * @return string
     */
    public function sign(array $values) : string
    {
        $values = serialize($values) . $this->secretKey;
        return hash_hmac('sha1', $values, $this->secretKey);
    }

    /**
     * @param string $sign
     * @param array $values
     *
     * @return bool
     */
    public function verify(string $sign, array $values) : bool
    {
        return hash_equals($this->sign($values), $sign);
    }

    /**
     * Parse Generator Json Data
     *  This to make check existing values on cookie
     *
     * @param string $jsonData
     *
     * @return string[]|bool
     */
    final public function parse(string $jsonData)
    {
        $jsonElements = json_decode($jsonData, true);

        unset($jsonData);
        if ($jsonElements === false
            || !is_array($jsonElements)
            || count($jsonElements) !== 5
            || array_keys($jsonElements) !== [
                static::USERNAME_KEY,
                static::EXPIRATION_KEY,
                static::TOKEN_KEY,
                static::HMAC_KEY,
                static::SIGN_KEY
            ]
        ) {
            unset($jsonElements);
            return false;
        }

        return $jsonElements;
    }

    /**
     * Validate Json data from generator token
     *
     * @param string $username user name
     * @param string $password stored database password,
     *                         must be encrypted password eg @uses password_hash()
     * @param string $scheme the scheme is commonly used as cookie name
     * @param string $jsonData
     *
     * @return string|false string the token generated otherwise false if invalid or expired
     *                      to known about expire or not, @uses parse() to get real value
     */
    final public function validate(
        string $username,
        string $password,
        string $scheme,
        string $jsonData
    ) {
        if (!is_array($jsonElements = $this->parse($jsonData))
            || empty($jsonElements)
        ) {
            return false;
        }

        $sign           = $jsonElements[static::SIGN_KEY];
        unset($jsonElements[static::SIGN_KEY]);
        if (!$this->verify($sign, $jsonElements)) {
            return false;
        }
        // check if expired
        $expired        = $jsonElements[static::EXPIRATION_KEY];
        if (!is_int($expired)
            || $expired < time()
        ) {
            return false;
        }

        $usernameStored = $jsonElements[static::USERNAME_KEY];
        $fragmentedUsername = $this->fragmentUsername($username);
        if (!is_string($usernameStored)
            || $fragmentedUsername !== $this->fragmentUsername($usernameStored)
        ) {
            return false;
        }

        $hmac           = $jsonElements[static::HMAC_KEY];
        $token          = $jsonElements[static::TOKEN_KEY];
        if (!is_string($hmac) || !is_string($token)) {
            return false;
        }

        // check password also if password does not match it will be not to process
        $pass_frag = $this->fragmentPassword($password);
        $key = $this->createHash(
            $fragmentedUsername . '|' . $pass_frag . '|' . $expired . '|' . $token,
            $scheme
        );

        $hash = hash_hmac('sha256', $fragmentedUsername . '|' . $expired . '|' . $token, $key);
        if (! hash_equals($hash, $hmac)) {
            return false;
        }

        return $token;
    }
}
