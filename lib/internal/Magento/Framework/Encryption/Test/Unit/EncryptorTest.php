<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Framework\Encryption\Test\Unit;

use Magento\Framework\Encryption\Encryptor;
use Magento\Framework\Encryption\Crypt;
use Magento\Framework\App\DeploymentConfig;

class EncryptorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Magento\Framework\Encryption\Encryptor
     */
    protected $_model;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    protected $_randomGenerator;

    protected function setUp()
    {
        $this->_randomGenerator = $this->getMock('Magento\Framework\Math\Random', [], [], '', false);
        $deploymentConfigMock = $this->getMock('\Magento\Framework\App\DeploymentConfig', [], [], '', false);
        $deploymentConfigMock->expects($this->any())
            ->method('get')
            ->with(Encryptor::PARAM_CRYPT_KEY)
            ->will($this->returnValue('cryptKey'));
        $this->_model = new \Magento\Framework\Encryption\Encryptor($this->_randomGenerator, $deploymentConfigMock);
    }

    public function testGetHashNoSalt()
    {
        $this->_randomGenerator->expects($this->never())->method('getRandomString');
        // the password API will be skipped when no salt is requested/used
        $expected = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8';
        $actual = $this->_model->getHash('password');
        $this->assertEquals($expected, $actual);
    }

    public function testGetHashSpecifiedSalt()
    {
        $this->_randomGenerator->expects($this->never())->method('getRandomString');
        // the password API should match the following pattern and ignore provided, invalid salt
        $expected = '/\$2y\$10\$[\.\/0-9A-Za-z]{22}.{31}/';
        $actual = $this->_model->getHash('password', 'salt');
        $this->assertRegExp($expected, $actual);
    }

    public function testGetHashRandomSaltDefaultLength()
    {
        $this->_randomGenerator
            ->expects($this->once())
            ->method('getRandomString')
            ->with(32)
            ->will($this->returnValue('-----------random_salt----------'));
        // the password API should match the following pattern and ignore random generated salt
        $expected = '/\$2y\$10\$[\.\/0-9A-Za-z]{22}.{31}/';
        $actual = $this->_model->getHash('password', true);
        $this->assertRegExp($expected, $actual);
    }

    public function testGetHashRandomSaltSpecifiedLength()
    {
        $this->_randomGenerator
            ->expects($this->once())
            ->method('getRandomString')
            ->with(11)
            ->will($this->returnValue('random_salt'));
        // the password API should match the following pattern and ignore random generated salt
        $expected = '/\$2y\$10\$[\.\/0-9A-Za-z]{22}.{31}/';
        $actual = $this->_model->getHash('password', 11);
        $this->assertRegExp($expected, $actual);
    }

    /**
     * @param string $password
     * @param string $hash
     * @param bool $expected
     *
     * @dataProvider validateHashDataProvider
     */
    public function testValidateHash($password, $hash, $expected, $expectsNeedRehash)
    {
        $actual = $this->_model->validateHash($password, $hash);
        $this->assertEquals($expected, $actual);
        $this->assertEquals($expectsNeedRehash, $this->_model->needsRehash($hash));
    }

    public function validateHashDataProvider()
    {
        return [
            ['password', 'hash', false, true],
            ['password', 'hash:salt', false, true],
            ['password', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', true, true],
            ['password', '67a1e09bb1f83f5007dc119c14d663aa:salt', true, true],
            ['password', '$2y$10$bRbkme0WLMhiKW1xmtPC0OxV.q0EbF0JghOETUBApr.0NOSu0d/o2', true, false]
        ];
    }

    /**
     * @param mixed $key
     *
     * @dataProvider encryptWithEmptyKeyDataProvider
     */
    public function testEncryptWithEmptyKey($key)
    {
        $deploymentConfigMock = $this->getMock('\Magento\Framework\App\DeploymentConfig', [], [], '', false);
        $deploymentConfigMock->expects($this->any())
            ->method('get')
            ->with(Encryptor::PARAM_CRYPT_KEY)
            ->will($this->returnValue($key));
        $model = new Encryptor($this->_randomGenerator, $deploymentConfigMock);
        $value = 'arbitrary_string';
        $this->assertEquals($value, $model->encrypt($value));
    }

    public function encryptWithEmptyKeyDataProvider()
    {
        return [[null], [0], [''], ['0']];
    }

    /**
     * @param mixed $key
     *
     * @dataProvider decryptWithEmptyKeyDataProvider
     */
    public function testDecryptWithEmptyKey($key)
    {
        $deploymentConfigMock = $this->getMock('\Magento\Framework\App\DeploymentConfig', [], [], '', false);
        $deploymentConfigMock->expects($this->any())
            ->method('get')
            ->with(Encryptor::PARAM_CRYPT_KEY)
            ->will($this->returnValue($key));
        $model = new Encryptor($this->_randomGenerator, $deploymentConfigMock);
        $value = 'arbitrary_string';
        $this->assertEquals('', $model->decrypt($value));
    }

    public function decryptWithEmptyKeyDataProvider()
    {
        return [[null], [0], [''], ['0']];
    }

    public function testEncrypt()
    {
        // sample data to encrypt
        $data = 'Mares eat oats and does eat oats, but little lambs eat ivy.';

        $actual = $this->_model->encrypt($data);

        // Extract the initialization vector and encrypted data
        $parts = explode(':', $actual, 4);
        list(, , $iv, $encryptedData) = $parts;

        // Decrypt returned data with latest cipher and mode (must match latest cipher)
        $crypt = new Crypt('cryptKey', Crypt::CIPHER_RIJNDAEL_128, Crypt::MODE_CTR, $iv);
        // Verify decrypted matches original data
        $this->assertEquals($data, $crypt->decrypt(base64_decode((string)$encryptedData)));
    }

    public function testDecrypt()
    {
        // sample data to encrypt
        $data = '0:2:z3a4ACpkU35W6pV692U4ueCVQP0m0v0p:' .
            '7ZPIIRZzQrgQH+csfF3fyxYNwbzPTwegncnoTxvI3OZyqKGYlOCTSx5i1KRqNemCC8kuCiOAttLpAymXhzjhNQ==';

        $actual = $this->_model->decrypt($data);
        $expected = 'Mares eat oats and does eat oats, but little lambs eat ivy.';
        $this->assertEquals($expected, $actual);

        // not testing for same encrypted values as the encryption padding algorithm may have changed
    }

    public function testEncryptDecryptNewKeyAdded()
    {
        $deploymentConfigMock = $this->getMock('\Magento\Framework\App\DeploymentConfig', [], [], '', false);
        $deploymentConfigMock->expects($this->at(0))
            ->method('get')
            ->with(Encryptor::PARAM_CRYPT_KEY)
            ->will($this->returnValue("cryptKey1"));
        $deploymentConfigMock->expects($this->at(1))
            ->method('get')
            ->with(Encryptor::PARAM_CRYPT_KEY)
            ->will($this->returnValue("cryptKey1\ncryptKey2"));
        $model1 = new Encryptor($this->_randomGenerator, $deploymentConfigMock);
        // simulate an encryption key is being added
        $model2 = new Encryptor($this->_randomGenerator, $deploymentConfigMock);

        // sample data to encrypt
        $data = 'Mares eat oats and does eat oats, but little lambs eat ivy.';
        // encrypt with old key
        $encryptedData = $model1->encrypt($data);
        $decryptedData = $model2->decrypt($encryptedData);

        $this->assertSame($data, $decryptedData, 'Encryptor failed to decrypt data encrypted by old keys.');
        $this->assertFalse($model1->needsReencrypt($encryptedData), 'Existing key should not need re-encryption.');
        $this->assertTrue($model2->needsReencrypt($encryptedData), 'New key should mean re-encryption needed.');
    }

    public function testValidateKey()
    {
        $actual = $this->_model->validateKey('some_key');
        $crypt = new Crypt('some_key', Crypt::CIPHER_RIJNDAEL_128, Crypt::MODE_CTR, $actual->getInitVector());
        $expectedEncryptedData = base64_encode($crypt->encrypt('data'));
        $actualEncryptedData = base64_encode($actual->encrypt('data'));
        $this->assertEquals($expectedEncryptedData, $actualEncryptedData);
        $this->assertEquals($crypt->decrypt($expectedEncryptedData), $actual->decrypt($actualEncryptedData));
    }
}
