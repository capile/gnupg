<?php

namespace Capile\Pgp\Test;
use Capile\Pgp;

class GpgTest extends \Codeception\Test\Unit
{
    /**
     * @var \Capile\Pgp\Test\UnitTester
     */
    protected $tester;

    protected static $Gpg,
            $create = [],
            $keys=[],
            $message,
            $secretMessage;
    
    protected function _before()
    {
        if(!self::$Gpg) {
            $root = dirname(dirname(dirname(__FILE__)));
            if(file_exists($root.'/gpg')) Pgp::$gpgCli=$root.'/gpg';

            Pgp::$gpgHome = tempnam($root.'/tests/_output', 'unit-test');
            unlink(Pgp::$gpgHome);
            mkdir(Pgp::$gpgHome, 0700);

            self::$Gpg = new Pgp();
        }
    }

    public function testVersionGreaterThan_2()
    {
        $version = self::$Gpg->version();
        $this->assertStringContainsString('gpg (GnuPG) 2.', $version);
    }

    public function testKeyCreation()
    {
        self::$create = [
            [
                'email'=>'expired',
                'expires'=>date('Ymd\THis', time()+1),
            ],
            [
                'name'=>' Test UTF8 😍',
                'email'=>'😍@example.com',
                'password'=>base64_encode(random_bytes(30)).'😍',
            ],
            [
                'name'=>'Example User',
                'email'=>'user@example.org',
                'comment'=>'Simplest Key possible',
                'expires'=>'2020-05-01',
            ],
        ];

        foreach(self::$create as $i=>$k) {
            self::$keys[$i] = self::$Gpg->create($k);
            $this->assertEquals(strlen(self::$keys[$i]), 40);
        }
    }

    public function testKeyExport()
    {
        foreach(self::$keys as $i=>$k) {
            $pub = self::$Gpg->export($k);
            $this->assertEquals(substr($pub, 0, 36), '-----BEGIN PGP PUBLIC KEY BLOCK-----');
            $this->assertEquals(substr($pub, -34), '-----END PGP PUBLIC KEY BLOCK-----');
        }
    }

    public function testEncryption()
    {
        static::$message = base64_encode(random_bytes(1000));

        // encrypt to key 1
        self::$Gpg->addencryptkey(self::$keys[1]);
        static::$secretMessage = trim(self::$Gpg->encrypt(self::$message));
        self::$Gpg->clearencryptkeys();

        $this->assertEquals(substr(static::$secretMessage, 0, 27), '-----BEGIN PGP MESSAGE-----');
        $this->assertEquals(substr(static::$secretMessage, -25), '-----END PGP MESSAGE-----');
    }

    public function testDecryption()
    {
        // decrypt using key 1
        self::$Gpg->adddecryptkey(self::$keys[1], self::$create[1]['password']);
        $msg = self::$Gpg->decrypt(self::$secretMessage);
        self::$Gpg->cleardecryptkeys();
        $this->assertEquals($msg, self::$message);
    }

    // this should be the ast one to clean up test dirs
    protected function testCleanup()
    {
        if(self::$Gpg) {
            self::$Gpg->destroyHome = true;
            self::$Gpg = null;
        }
    }
}