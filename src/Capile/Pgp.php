<?php

namespace Capile;

class Pgp
{
    public static 
        $gpgHome,
        $gpgCli='gpg',
        $gpgAgent='gpg-agent',
        $startAgent,
        $defaultOptions='--batch',
        $defaultConfig=[
            'with-fingerprint',
            'keyid-format long',
            'armor',
            'utf8-strings',
            'no-secmem-warning',
            'no-permission-warning',
            'no-mdc-warning',
            'no-emit-version',
            'personal-digest-preferences SHA512 SHA256 SHA384 SHA224',
            'cert-digest-algo SHA512',
            'personal-cipher-preferences AES256 AES192 AES CAST5',
            'default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB ZIP Uncompressed',
            'no-comments',
            'expert',
            'no-auto-check-trustdb',
            'no-sig-cache',
            'pinentry-mode loopback',
        ],
        $defaultCreate=[
            'type' => 'RSA',
        ],
        $sanitizeInput=true,
        $logDir='error_log',
        $acceptedErrorCodes=[2];

    protected 
        $home,
        $encryptKeys=[],
        $decryptKeys=[],
        $signKeys=[],
        $error,
        $errorMessage;
    protected static $passphrase=[];
    public $destroyHome;

    public function __construct($gpghome=null)
    {
        // shoud set default options if no GNUPGHOME/gpg.conf file exists
        if(is_null(static::$gpgHome)) {
            if($h=getenv('GNUPGHOME')) static::$gpgHome = $h;
            else static::$gpgHome = '~/.gnupg';
        }
        if(is_dir(static::$gpgHome)) {
            $this->home = realpath(static::$gpgHome);
        } else {
            $this->home = tempnam(sys_get_temp_dir(), 'gpg');
            unlink($this->home);
            mkdir($this->home, 0700);
            $this->destroyHome = true;
        }

        if(!file_exists($this->home.'/gpg.conf')) {
            file_put_contents($this->home.'/gpg.conf', implode("\n", static::$defaultConfig));
        }

        if(static::$startAgent) {
            @exec('pgrep -fa gpg-agent', $output, $result);
            if($result==1 && !$output) {
                $cmd = static::$gpgAgent.' --daemon';
                if(strpos($cmd, 'GNUPGHOME=')===false) {
                    $cmd = 'GNUPGHOME='.$this->home.' '.$cmd;
                }
                @exec($cmd, $output, $result);
            }
        }
    }

    public function __destruct()
    {
        if($this->home && $this->destroyHome) {
            if($g=glob($this->home.'/*')) {
                $d = [];
                while($g) {
                    $f = array_shift($g);
                    $b = basename($f);
                    if($b==='.' || $b==='..') {
                        continue;
                    } else if(is_dir($f)) {
                        $n = glob($f.'/*');
                        if($n) {
                            $n[] = $f;
                            $g = array_merge($n, $g);
                            if(in_array($f, $d)) {
                                continue;
                            }
                            $d[] = $f;
                        } else {
                            rmdir($f);
                        }
                    } else {
                        unlink($f);
                    }
                }
            }
            rmdir($this->home);
        }
    }

    public function create($options)
    {
        static $map=[
            'type' => 'Key-Type',           // RSA
            'size' => 'Key-Length',         // 4096
            'subtype' => 'Subkey-Type',     // RSA
            'subsize' => 'Subkey-Length',   // 4096
            'name' => 'Name-Real',
            'comment' => 'Name-Comment',
            'email' => 'Name-Email',
            'expire' => 'Expire-Date',
            'expires' => 'Expire-Date',
            'password' => 'Passphrase',
        ];

        $key = static::$defaultCreate + $options;

        $s = '';
        foreach($key as $n=>$v) {
            if(isset(static::$defaultCreate[$n]) && isset($options[$n])) {
                $v = $options[$n];
            }
            if(isset($map[$n])) {
                $n = $map[$n];
            }
            $s .= $n.': '.$v."\n";
        }

        if(!strpos($s, 'Passphrase')) {
            // enabled for tests only
            $s .= "%no-protection\n%transient-key\n";
        }
        $s .= '%commit';

        $pwd = getcwd();
        if($pwd!=$this->home) {
            chdir($this->home);
        }
        $f = tempnam($this->home, 'new');
        file_put_contents($f, $s);
        $res = $this->run(['--gen-key', basename($f)]);
        if($pwd!=$this->home) {
            chdir($pwd);
        }

        if($res) {
            foreach($res as $ln) {
                if(preg_match('/^gpg: key (0x)?([A-F0-9]+)/', $ln, $m)) {
                    return $this->keyinfo($m[2], 'fingerprint')[0];
                }
            }
        }
    }

    public function import($keydata)
    {
        if(static::$sanitizeInput) {
            $keydata = preg_replace('#[^a-z0-9=/\+\n\- ]+#i', '', $keydata);
        }

        $f = tempnam($this->home, 'key');
        file_put_contents($f, $keydata);
        $res = $this->run(['--import', $f]);
        unlink($f);

        if($res) {
            $r = [
              'imported' => 0,
              'unchanged' => 0,
              'newuserids' => 0,
              'newsubkeys' => 0,
              'secretimported' => 0,
              'secretunchanged' => 0,
              'newsignatures' => 0,
              'skippedkeys' => 0,
              'fingerprint' => null,
            ];

            $ids = [];
            foreach($res as $i=>$ln) {
                if(preg_match('#^gpg: ([^\:]+): (.*)#', $ln, $m)) {
                    $m[1] = trim($m[1]);
                    if(substr($m[1], 0, 4)==='key ') {
                        $ids[] = substr($m[1], 4);
                    } else if(isset($r[$m[1]]) && is_numeric($m[2])) {
                        $r[$m[1]] += (int) $m[2];
                    }
                }
                unset($res[$i], $i, $ln, $m);
            }

            // expand ids to fingerprint, get only the first one
            if($ids) {
                $r['ids'] = $ids;
                $res = $this->keyinfo($ids[0], 'fingerprint');
                if($res && isset($res[0])) {
                    $r['fingerprint'] = $res[0];
                }
                unset($res);
            }

            return $r;
        }
    }

    public function fingerprint($search)
    {
        return $this->keyinfo($search, 'fingerprint');
    }

    public function export($search)
    {
        $res = $this->run(['--export', $search]);

        if($res) {
            return implode("\n", $res);
        }
    }

    public function keyinfo($search, $prop=null)
    {
        static 
            $key0 = [
                'disabled' => null,
                'expired' => null,
                'revoked' => null,
                'invalid' => null,
                'is_secret' => null,
                'can_sign' => null,
                'can_encrypt' => null,
                'size' => null,
                'uids' => [],
                'subkeys' => [],
            ],
            $uid0 = [
                'name' => null,
                'comment' => null,
                'email' => null,
                'uid' => null,
                'revoked' => null,
                'expired' => null,
                'invalid' => null,
            ],

            $subkey0 = [
                'fingerprint' => null,
                'keyid' => null,
                'timestamp' => null,
                'expires' => null,
                'is_secret' => null,
                'invalid' => null,
                'can_encrypt' => null,
                'can_sign' => null,
                'disabled' => null,
                'expired' => null,
                'revoked' => null,
            ];


        $cmd = ($prop && $prop!='sigs') ?'--list-sigs' :'--list-keys';

        $res = $this->run([$cmd, '--with-colons', $search]);

        if(!$res) return;

        $keyid = -1;
        $subid = -1;
        $uid = -1;
        $r = [];
        $txt = implode("\n", $res);

        while($res) {
            $ln = array_shift($res);
            if(!$ln || !($c=explode(':', $ln)) || $c[0]==='tru') continue;

            if($c[0]==='pub' || $c[0]==='sub') {
                $nxt = explode(':', array_shift($res));
                $fpr = $nxt[9];

                if($c[0]==='pub') {
                    $keyid++;
                    $subid = 0;
                    $uid = -1;
                    $r[$keyid] = ['fingerprint'=>$fpr]+$key0;
                } else {
                    $subid++;
                }

                $r[$keyid]['subkeys'][$subid] = [
                    'fingerprint' => $fpr,
                    'keyid' => $c[4],
                    'timestamp' => $c[5],
                ] + $subkey0;

                if(is_numeric($c[2])) {
                    $r[$keyid]['size'] = (int) $c[2];
                }
                // if it's not disabled or revoked or expired
                $disabled = null;
                $revoked = null;
                $expired = null;
                $invalid = null;

                if($c[1]==='r') {
                    $revoked = true;
                    $r[$keyid]['subkeys'][$subid]['revoked'] = true;
                } else if($c[1]==='e') {
                    $revoked = true;
                    $r[$keyid]['subkeys'][$subid]['expired'] = true;
                }

                if(is_numeric($c[6])) {
                    $r[$keyid]['subkeys'][$subid]['expires'] = (int) $c[6];
                    if($r[$keyid]['subkeys'][$subid]['expires'] < time()) {
                        $expired = true;
                        $r[$keyid]['subkeys'][$subid]['expired'] = true;
                    }
                }


                $valid = (is_null($disabled) && is_null($revoked) && is_null($expired) && is_null($invalid));
                if(strpos($c[11], 's')!==false) {
                    $r[$keyid]['subkeys'][$subid]['can_sign'] = true;
                }
                if(strpos($c[11], 'e')!==false) {
                    $r[$keyid]['subkeys'][$subid]['can_encrypt'] = true;
                }
                if(strpos($c[11], 'a')!==false) {
                    $r[$keyid]['subkeys'][$subid]['is_secret'] = true;
                }
            } else if($c[0]==='sig') {
            } else if($c[0]==='uid') {
                $uid++;

                $name = null;
                $email = null;
                $comment = null;
                if(preg_match('/^(.*)( \([^\)]+\))?( <[^>]+>)$/', $c[9], $m)) {
                    $name = $m[1];
                    $email = substr($m[3], 2, strlen($m[3]) -3);
                    $comment = ($m[2]) ?substr($m[2], 2, strlen($m[2]) -3) :null;
                }

                $r[$keyid]['uids'][$uid] = [
                    'uid'=>$c[9],
                    'name'=>$name,
                    'email'=>$email,
                    'comment'=>$comment,
                    'timestamp'=>(int)$c[5],
                ] + $uid0;

                // check revoked
                // check invalid
                if($c[1]==='r') {
                    $revoked = true;
                    $r[$keyid]['uids'][$uid]['revoked'] = true;
                    $r[$keyid]['uids'][$uid]['invalid'] = true;
                } else if($c[1]==='e') {
                    $revoked = true;
                    $r[$keyid]['uids'][$uid]['expired'] = true;
                    $r[$keyid]['uids'][$uid]['invalid'] = true;
                }

            }
        }

        $ret = [];
        if($r) {
            // check subkeys to update master one
            foreach($r as $i=>$o) {
                $disabled = null;
                $revoked = null;
                $expired = null;
                $invalid = null;
                $is_secret  = null;
                $can_sign = null;
                $can_encrypt = null;
                if($o['subkeys']) {
                    foreach ($o['subkeys'] as $keyid => $k) {
                        if($k['disabled']) {
                            $disabled = true;
                        } else if($disabled) {
                            $disabled = null;
                        }
                        if($k['revoked']) {
                            $revoked = true;
                        } else if($revoked) {
                            $revoked = null;
                        }
                        if($k['expired']) {
                            $expired = true;
                        } else if($expired) {
                            $expired = null;
                        }
                        if($k['invalid']) {
                            $invalid = true;
                        } else if($invalid) {
                            $invalid = null;
                        }
                        if($k['is_secret']) {
                            $is_secret = true;
                        }
                        if(is_null($disabled) && is_null($revoked) && is_null($expired) && is_null($invalid)) {
                            if($k['can_sign']) {
                                $can_sign = true;
                            }
                            if($k['can_encrypt']) {
                                $can_encrypt = true;
                            }
                        }
                        unset($keyid, $k);
                    }
                }
                $r[$i]['disabled'] = $disabled;
                $r[$i]['revoked']  = $revoked;
                $r[$i]['expired']  = $expired;
                $r[$i]['invalid']  = $invalid;
                $r[$i]['is_secret'] = $is_secret;
                $r[$i]['can_sign'] = $can_sign;
                $r[$i]['can_encrypt'] = $can_encrypt;

                if($prop) {
                    if(isset($r[$i][$prop])) {
                        $ret[$i] = $r[$i][$prop];
                    } else if(isset($o['subkeys'][0][$prop])) {
                        $ret[$i] = $o['subkeys'][0][$prop];
                    }
                }
                unset($i, $o);
            }
        }

        if($prop) {
            return $ret ?$ret :null;
        }

        return $r;
    }

    public function addencryptkey($key)
    {
        $this->encryptKeys[] = $key;
    }

    public function clearencryptkeys()
    {
        $this->encryptKeys = [];
    }

    public function addsignkey($key, $pass=null)
    {
        $this->signKeys[] = $key;
        if(!is_null($pass)) {
            self::$passphrase['sign-'.$key] = $pass;
        }
    }

    public function clearsignkeys()
    {
        foreach($this->decryptKeys as $i=>$k) {
            if(isset(self::$passphrase['sign-'.$key])) {
                unset(self::$passphrase['sign-'.$key]);
            }
            unset($this->decryptKeys[$i], $i, $k);
        }
    }

    public function adddecryptkey($key, $pass=null)
    {
        $this->decryptKeys[] = $key;
        if(!is_null($pass)) {
            self::$passphrase['decrypt-'.$key] = $pass;
        }
    }

    public function cleardecryptkeys()
    {
        foreach($this->decryptKeys as $i=>$k) {
            if(isset(self::$passphrase['decrypt-'.$k])) {
                unset(self::$passphrase['decrypt-'.$k]);
            }
            unset($this->decryptKeys[$i], $i, $k);
        }
    }

    public function encrypt($msg)
    {
        $f = tempnam($this->home, 'enc');
        file_put_contents($f, $msg);

        $cmd = ['-e', '-a', '--trust-model', 'always'];
        foreach($this->encryptKeys as $k) {
            $cmd[] = '-r';
            $cmd[] = $k;
        }

        $cmd[] = '--output';
        $cmd[] = $f.'.asc';
        $cmd[] = $f;
        $res = $this->run($cmd);
        unlink($f);

        if(file_exists($f.'.asc')) {
            $res = file_get_contents($f.'.asc');
            unlink($f.'.asc');
        } else if(is_array($res)) {
            $res = implode("\n", $res);
        }

        if($res) {
            return $res;
        }
    }

    public function decrypt($msg)
    {
        $f = tempnam($this->home, '.dec');
        file_put_contents($f, $msg);

        $cmd = ['-d', '--batch'];
        // only the first decryption key will be used
        foreach($this->decryptKeys as $k) {
            $secret = $this->keyinfo($k, 'is_secret');
            print_r([$k, $secret, self::$passphrase['decrypt-'.$k]]);
            if($secret && isset(self::$passphrase['decrypt-'.$k])) {
                $pf = tempnam($this->home, '.sec');
                file_put_contents($pf, self::$passphrase['decrypt-'.$k]);
                $cmd[] = '--passphrase-file';
                $cmd[] = $pf;
                break;
            }
        }

        $cmd[] = '--output';
        $cmd[] = $f.'.txt';
        $cmd[] = $f;

        $res = $this->run($cmd);
        unlink($f);
        if(isset($pf)) {
            unlink($pf);
            unset($pf);
        }

        if(file_exists($f.'.txt')) {
            $res = file_get_contents($f.'.txt');
            unlink($f.'.txt');
        } else if(is_array($res)) {
            $res = implode("\n", $res);
        }

        if($res) {
            return $res;
        }
    }

    public function sign()
    {
        // not implemented yet
    }

    public function geterror($number=null)
    {
        return ($number) ?$this->error :$this->errorMessage;
    }

    public function clearerror()
    {
        if($this->error) {
            $this->error = null;
            $this->errorMessage = null;
        }
    }

    public function version()
    {
        return $this->run('-h')[0];
    }

    public function run($options, $files=null)
    {
        if($this->home && getenv('GNUPGHOME')!=$this->home) {
            putenv('GNUPGHOME='.strtr(preg_replace('#[^a-z0-9 /_\-]+#i', '', $this->home), [' '=>'\\ ']));
        }

        $this->clearerror();

        $cmd = static::$gpgCli.' '.static::$defaultOptions;
        if(is_array($options)) {
            foreach($options as $a) {
                $cmd .= ' '.(preg_match('/^[a-z0-9\-]+$/i', $a) ?$a :escapeshellarg($a));
            }
        } else {
            $cmd .= ' '.(preg_match('/^[a-z0-9\-]+$/', $options) ?$options :escapeshellarg($options));
        }
        $cmd .= ' 2>&1';

        @exec($cmd, $output, $result);
        if($result==0 || in_array($result, static::$acceptedErrorCodes)) return $output;

        $this->error = $result;

        if($output) {
            $e = false;
            foreach($output as $ln) {
                if($e && substr($ln, 0, 4)==='tru:') {
                    break;
                } else if($e || preg_match('/^gpg: error /', $ln)) {
                    $e = true;
                    $this->errorMessage .= $ln."\n";
                }
            }
        }

        $this->log('[ERROR] PGP Error: '.$this->error, $cmd, implode("\n", $output));

        return;
    }

    /**
     * Error messages logger
     *
     * Pretty print the objects to the PHP's error_log
     *
     * @param   mixed  $var  value to be displayed
     *
     * @return  void
     */
    public function log()
    {
        static $trace;
        $logs = array();
        $d = (!is_array(self::$logDir))?(array(self::$logDir)):(self::$logDir);
        foreach($d as $l) {
            if($l=='syslog' && openlog('capile-pgp', LOG_PID|LOG_NDELAY, LOG_LOCAL5)) {
                $logs['syslog'] = true;
            } else if($l=='error_log') {
                $logs[0] = true;
            } else if($l=='cli') {
                $logs[2] = true;
            } else {
                if(!$l) {
                    $l = $this->home;
                }
                if(is_dir($l)) $l .= '/gpgerror.log';
                $logs[3] = $l;
            }
            unset($l);
        }
        unset($d);

        foreach (func_get_args() as $k => $v) {
            if(!is_string($v)) {
                $v = (function_exists('json_encode')) ?json_encode($v,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) :serialize($v);
            }
            $v .= "\n";
            if(isset($logs['syslog'])) {
                $l = LOG_INFO;
                if(substr($v, 0, 4)=='[ERR') $l = LOG_ERR;
                else if(substr($v, 0, 5)=='[WARN') $l = LOG_WARNING;
                else $l = LOG_INFO;
                syslog($l, $v);
            }
            if(isset($logs[3])) {
                error_log($v, 3, $logs[3]);
            }
            if(isset($logs[0])) {
                error_log($v, 0);
            }
            if(isset($logs[2])) {
                echo $v;
            }
            unset($v, $k);
        }

        if(isset($logs['syslog'])) {
            closelog();
        }
        unset($logs);
    }

}