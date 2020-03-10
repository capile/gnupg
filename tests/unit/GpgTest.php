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
            if(file_exists($root.'/gpg_alias')) Pgp::$gpgCli=file_get_contents($root.'/gpg_alias');

            Pgp::$gpgHome = tempnam($root.'/tests/_output', 'unit-test');
            Pgp::$logDir = [ Pgp::$gpgHome, 'cli' ];
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

    public function testError()
    {
        // run an invalid command
        $this->assertEquals(null, self::$Gpg->run(['--list-keys', 'xxxxxxxxxxxxx']));
    }

    public function testInitialization()
    {
        // GNUPGHOME/pubring.* should have been created
        $this->assertEquals(1, count(glob(Pgp::$gpgHome.'/pubring.*')));
    }

    public function testImport()
    {
        $root = dirname(dirname(dirname(__FILE__)));
        foreach(glob($root.'/tests/_data/*.asc') as $f) {
            $res = self::$Gpg->import(file_get_contents($f));
            $this->assertArrayHasKey('fingerprint', $res, 'Key imported?');

            // uid, property must exist, id, number of keys
            $prop = explode('.', basename($f, '.asc'));

            $this->assertEquals((int)$prop[3], count($res['ids']), 'Correct number of keys');
            $this->assertEquals($prop[2], $res['ids'][0], 'Correct key id');

            $K = self::$Gpg->keyinfo($res['fingerprint']);
            $this->assertArrayHasKey($prop[1], $K[0]);
            $this->assertEquals($prop[0], $K[0]['uids'][0]['uid']);

        }
    }

    public function testKeyCreation()
    {
        self::$create = [
            [
                'email'=>'1',
                'expires'=>date('Ymd\THis', time()+1),
                'password'=>'1',
            ],
            [
                'name'=>' Test UTF8 😍',
                'email'=>'😍@example.com',
                'password'=>base64_encode(random_bytes(30)).'😍',
            ],
            [
                'Key-Type' => 'DSA',
                'Key-Length' => 1024,
                'Subkey-Type' => 'ECDSA',
                'Subkey-Curve' => 'nistp256',
                'Name-Real'=>'Example User',
                'Name-Email'=>'user@example.org',
                'Name-Comment'=>'new Elliptic Curves key',
                'Expire-Date'=>0,
                'Passphrase'=>base64_encode(random_bytes(30)),
            ],
        ];

        foreach(self::$create as $i=>$k) {
            if(!(self::$keys[$i] = self::$Gpg->create($k))) {
                /*
                if(file_exists(Pgp::$gpgHome.'/gpgerror.log')) {
                    echo file_get_contents(Pgp::$gpgHome.'/gpgerror.log'), "\n";
                    exit();
                }*/
            }
            $this->assertEquals(strlen(self::$keys[$i]), 40);
        }
    }

    public function testKeyExport()
    {
        foreach(self::$keys as $i=>$k) {
            $pub = self::$Gpg->export($k);
            if(!$pub) {
                /*
                if(file_exists(Pgp::$gpgHome.'/gpgerror.log')) {
                    echo file_get_contents(Pgp::$gpgHome.'/gpgerror.log'), "\n";
                    exit();
                }
                */
            }
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

        if(!static::$secretMessage) {
            if(self::$Gpg->geterror() && file_exists(Pgp::$gpgHome.'/gpgerror.log')) {
                echo file_get_contents(Pgp::$gpgHome.'/gpgerror.log'), "\n";
                exit();
            }
        }

        $this->assertEquals(substr(static::$secretMessage, 0, 27), '-----BEGIN PGP MESSAGE-----');
        $this->assertEquals(substr(static::$secretMessage, -25), '-----END PGP MESSAGE-----');
    }

    public function testDecryption()
    {
        // decrypt using key 1
        self::$Gpg->adddecryptkey(self::$keys[1], self::$create[1]['password']);
        $msg = self::$Gpg->decrypt(self::$secretMessage);
        self::$Gpg->cleardecryptkeys();

        if(!$msg) {
            exit(self::$Gpg->geterror());
            if(self::$Gpg->geterror() && file_exists(Pgp::$gpgHome.'/gpgerror.log')) {
                echo file_get_contents(Pgp::$gpgHome.'/gpgerror.log'), "\n";
                exit();
            }
        }
        $this->assertEquals(self::$message, $msg);
    }

    // this should be the ast one to clean up test dirs
    protected function testCleanup()
    {
        if(self::$Gpg) {
            self::$Gpg->destroyHome = true;
            self::$Gpg = null;
            if(self::$Gpg->geterror() && file_exists(Pgp::$gpgHome.'/gpgerror.log')) {
                echo file_get_contents(Pgp::$gpgHome.'/gpgerror.log');
                exit();
            }
            $this->assertEquals(false, file_exists(Pgp::$gpgHome));
        }
    }
}