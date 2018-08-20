<?php

namespace Illuminate\Tests\Encryption;

use PHPUnit\Framework\TestCase;
use Illuminate\Encryption\Encrypter;

/**
 * Test Class for Encypter.php
 *
 * @source https://github.com/laravel/framework/blob/5.0/tests/Encryption/EncrypterTest.php,
 *         https://github.com/laravel/framework/blob/5.6/tests/Encryption/EncrypterTest.php
 *
 */
class EncrypterTest extends TestCase
{

    public function setUp()
    {
        $this->strDemo = str_repeat('a', 32);
    }

    public function testEncryption()
	{
		$e = $this->getEncrypter();

		$this->assertNotEquals($this->strDemo, $e->encrypt($this->strDemo));

		$encrypted = $e->encrypt($this->strDemo);

		$this->assertEquals($this->strDemo, $e->decrypt($encrypted));
	}

    public function testRawStringEncryption()
    {
        $e = new Encrypter(str_repeat('a', 16));

        $encrypted = $e->encryptString('foo');

        $this->assertNotEquals('foo', $encrypted);

        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testEncryptionUsingBase64EncodedKey()
    {
        $e = new Encrypter(random_bytes(16));

        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);

        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithCustomCipher()
    {
        $e = new Encrypter(str_repeat('b', 32), 'AES-256-CBC');

        $encrypted = $e->encrypt('bar');

        $this->assertNotEquals('bar', $encrypted);

        $this->assertEquals('bar', $e->decrypt($encrypted));

        $e = new Encrypter(random_bytes(32), 'AES-256-CBC');

        $encrypted = $e->encrypt('foo');

        $this->assertNotEquals('foo', $encrypted);

        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    /**
     * @exceptedException \Exception
     */
	public function testExceptionThrownWhenEncryptWithInvalidValue()
	{
		$e = $this->getEncrypter();

		$e->encrypt(false);
	}

	/**
	 * @expectedException Illuminate\Contracts\Encryption\DecryptException
	 */
	public function testExceptionThrownWhenPayloadIsInvalid()
	{
		$e = $this->getEncrypter();

		$payload = $e->encrypt('foo');

		$payload = str_shuffle($payload);

		$e->decrypt($payload);
	}

	protected function getEncrypter()
	{
		return new Encrypter($this->strDemo);
	}
}
