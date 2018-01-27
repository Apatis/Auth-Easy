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

namespace Apatis\Auth\Easy;

/**
 * Class AuthCookie
 * @package Apatis\Auth
 * @see http://browsercookielimits.squawky.net/ for list of cookie length limit
 * for save it must be less than 4000-bytes
 */
class AuthCookie
{
    /**
     * @var string
     */
    protected $secretKey;

    /**
     * @var Generator
     */
    protected $generator;

    /**
     * @var bool
     */
    protected $encrypted;

    /**
     * AuthCookie constructor.
     *
     * @param string $secretKey
     * @param bool $encrypted
     */
    public function __construct(string $secretKey, bool $encrypted = false)
    {
        $this->secretKey = $secretKey;
        $this->generator = new Generator($secretKey);
        $this->encrypted = $encrypted;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function encrypt(string $data) : string
    {
        return CryptOpenSSL::encrypt($data, $this->secretKey);
    }

    /**
     * @param string $data
     *
     * @return string|false false if returning invalid values
     */
    public function decrypt(string $data)
    {
        return CryptOpenSSL::decrypt($data, $this->secretKey);
    }

    /**
     * Get Generator
     *
     * @return Generator
     */
    public function getGenerator() : Generator
    {
        return $this->generator;
    }

    /**
     * Generate The Cookie Value
     *
     * @param string $userName
     * @param string $password
     * @param string $scheme
     * @param string $token the token name
     * @param int $expiration
     *
     * @return string
     */
    final public function generate(
        string $userName,
        string $password,
        string $scheme,
        string $token,
        int $expiration = null
    ) : string {
        return $this->normalizeEncodeValues(
            $this->getGenerator()->generate(
                $userName,
                $password,
                $scheme,
                $expiration,
                $token
            )
        );
    }

    /**
     * Parse Generator Json Data
     *  This to make check existing values on cookie
     *
     * @param string $data
     *
     * @return string[]|false if return fail
     */
    final public function parse(string $data)
    {
        if (!($data = $this->normalizeDecodeValues($data))) {
            return false;
        }

        return $this->getGenerator()->parse($data);
    }

    /**
     * Validate Json data from generator token
     *
     * @param string $username user name
     * @param string $password stored database password,
     *                         must be encrypted password eg @uses password_hash()
     * @param string $scheme the scheme is commonly used as cookie name
     * @param string $data
     *
     * @return string|false string the token generated otherwise false if invalid or expired
     *                      to known about expire or not, @uses parse() to get real value
     */
    final public function validate(
        string $username,
        string $password,
        string $scheme,
        string $data
    ) {
        if (!($data = $this->normalizeDecodeValues($data))) {
            return false;
        }

        return $this->getGenerator()->validate($username, $password, $scheme, $data);
    }

    /**
     * Normalize Decode for cookie values
     *
     * @param string $data
     *
     * @return false|string false if invalid
     */
    protected function normalizeDecodeValues(string $data)
    {
        $data = rawurldecode($data);
        if ($this->encrypted && !($data = $this->decrypt($data))) {
            return false;
        }

        return $data;
    }

    /**
     * Normalize Encode for cookie values
     *
     * @param string $data
     *
     * @return false|string false if invalid or string contains encoded values ready for cookie
     */
    protected function normalizeEncodeValues(string $data) : string
    {
        if ($this->encrypted) {
            $data = $this->encrypt($data);
        }

        return rawurlencode($data);
    }
}
