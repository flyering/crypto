<?php

namespace wpfly;

class Crypto
{
    private $s = [5, 6, 9, 4, 2, 7, 1, 0, 3, 8];
    private $_s = [7, 6, 4, 8, 3, 0, 1, 5, 9, 2];

    private $passPhrase = null;
    private $privateKey = <<<PK
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCoY1q8bXlmDNH6
M8rcCIzYhyZ622vk0dNtjjW3au3YuMMwuHpzstBxdrbdgiI6F/Hvsk1HNs07F09x
HeAGh36HPRNl9SleRjQ8oOgX3oBVMx0TGBzqRtROu9fq7Gh2Nebz//guU4BoF2Ku
/n9VSdsmFw1SV6qHAA41TpMDX2MlknjvfGnf13L068AvcW+vL6IGn66+fCjmD+Pj
GM9z/JZFNa47poH+I0fQ66mvSK7bIMCUVdj7jxOZCypAMegM0wtWrhBXjAZMVDgM
0EZKnKuFvy2nbjAX7WzErTB2aqEAwxGzvETvApE9jtOXajNiNk6O8evUaprW0MbP
wpouo2anAgMBAAECggEACFUaSVa1eipKPbJQaID3z0Mo0U2IUkNbzgEKgXAGIwJJ
jmCilpUToXm5ZM6quOs0aqMNFegNUc4+fR94VXpg9Xo9On9eM68PqKxhr8Sv3wdv
eeFolOM6YEcFUTevl6HlMs/IzSoOoZf+pyAq1uKXuJPNcfSqmJGVImgn+DPBKTu4
rbNyMYKyXY88x8Nl3TTbYPCIxQl1xgTcapBTVfJPHNy0zKK1RNuG26e7gXxX7wtQ
cgIJr5Dabi3F1H824DiX/CGQxa6++2F7/C5SZFHeqdXzXapLFak9UHmER5laF31t
DCiC3qLfqiUJ4t7UGmXPXYQDemHuxeij8tgQCHBt2QKBgQDeSiSBpavgMtiaLghp
yvFeWG55eZfza5mr3y5/6ddNcOzibLYVaEf6BA98Uh6oitGo8NyKDc3CE8cTdFPq
zE1/E555JCwZpQshjmTwk3j0CKJeR2zKodaMKvOrZlGoQew2N/paQC+Ht8aKsfYl
9rJzFkPU9oq86ehFrqxL0p3HNQKBgQDB7J2ebCW91rWUIC63YNTVk4SDDuD8wx1g
tuQVGmVMrwoQ7qH3UOE/Lp6DT8GiRF6az2embLnRy1kWEIpxLe8Sy9G1uwfGmEAP
VjcIJXnXPtwklK9RuuYYRnUFF9zYJ/IMiZtQL+kJmZ6aNf5vXaDs+F+0AOQeCV9l
75dhqPOF6wKBgAuVQ3e6AU3KeHz4Pxn8KD2pUABmdKOLjNNm6s5higWQB9f4oDhX
WcDOa1woD07rBOfPvT44X+toCmyaGDFY+gTQKebYGrAvaHgUKnBazuewd32ALUwV
yM8/AbmBuGmTHdLpcdM4GwHwcpkRkukBhOT4WQqE2k/jxGW1J2dAD1atAoGAEdP3
9Z2Jprc7gD+pK9CqIGxsbUQL6RDi/YYy18HSeEdLTJ0zpLH50z4s8nN9oLZaYC8b
H1C1kJT6Pq4MnDUV2ouEXwmvwFE06nQJoSUY23H6+R32NDRTfP3VOj+kXPbnKMHp
1mhhKzHFQ/Ycyw43gjGfUsQWNLC15YAuUZsfsDsCgYA3xpArpeYZw34SAudxE/V1
dOlMq+RHdFoEfC17gsxzwnem4iv3jKj97P6yEyQYVW9nijU4mzgAuHIxiRsZ7y1g
NncJ4hlEz4IVtsjS4+Dm8iuKJn6D+irNH/Taf6pOtUFtd+qRefm/JfRclSlk5gdN
1Ks2i+WaZSkreYzu2nq39Q==
-----END PRIVATE KEY-----
PK;
    private $publicKey = <<<PK
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGNavG15ZgzR+jPK3AiM
2Icmettr5NHTbY41t2rt2LjDMLh6c7LQcXa23YIiOhfx77JNRzbNOxdPcR3gBod+
hz0TZfUpXkY0PKDoF96AVTMdExgc6kbUTrvX6uxodjXm8//4LlOAaBdirv5/VUnb
JhcNUleqhwAONU6TA19jJZJ473xp39dy9OvAL3Fvry+iBp+uvnwo5g/j4xjPc/yW
RTWuO6aB/iNH0Oupr0iu2yDAlFXY+48TmQsqQDHoDNMLVq4QV4wGTFQ4DNBGSpyr
hb8tp24wF+1sxK0wdmqhAMMRs7xE7wKRPY7Tl2ozYjZOjvHr1Gqa1tDGz8KaLqNm
pwIDAQAB
-----END PUBLIC KEY-----
PK;

    private function numberDiffusion($m, $p)
    {
        $mLen = count($m);
        $pLen = count($p);
        $round = $mLen > $pLen ? $mLen : $pLen;
        for ($i = 0; $i < $round; $i++) {
            $mCurrent = $i % $mLen;
            $mNext = ($i + 1) % $mLen;
            $mPrev = ($i - 1 + $mLen) % $mLen;
            $pCurrent = $i % $pLen;
            $m[$mNext] = $this->s[($m[$mCurrent] + $m[$mNext] + $p[$pCurrent]) % 10];
            $m[$mCurrent] = $this->s[($m[$mPrev] + $m[$mCurrent] + $p[$pCurrent]) % 10];
        }
        return $m;
    }
    private function numberRecovery($d, $p)
    {
        $dLen = count($d);
        $pLen = count($p);
        $round = $dLen > $pLen ? $dLen : $pLen;
        for ($i = $round - 1; $i >= 0; $i--) {
            $dCurrent = $i % $dLen;
            $dNext = ($i + 1) % $dLen;
            $dPrev = ($i - 1 + $dLen) % $dLen;
            $pCurrent = $i % $pLen;
            $d[$dCurrent] = ($this->_s[$d[$dCurrent]] - $d[$dPrev] - $p[$pCurrent] + 20) % 10;
            $d[$dNext] = ($this->_s[$d[$dNext]] - $d[$dCurrent] - $p[$pCurrent] + 20) % 10;
        }
        return $d;
    }
    function generateMap()
    {
        $s = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        shuffle($s);
        $_s = array_flip($s);
        ksort($_s);
        return "\$s = [" . implode(',', $s) . "]; \$_s = [" . implode(',', $_s) . "];";
    }
    function setMap($map)
    {
        if(!is_array($map))
        {
            throw new \Exception('Parameter $num must be an array.');
        }
        $temp = $map;
        sort($temp);
        if($temp != [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        {
            throw new \Exception('Parameter $map must be a permutation of 0 to 9.');
        }
        $this->s = $map;
        $this->_s = array_flip($map);
        ksort($this->_s);
    }
    function numberEncrypt($num, $key, $fill = 0)
    {
        if (!is_string($num)) {
            throw new \Exception('Parameter $num must be a string.');
        }
        if (!is_string($key)) {
            throw new \Exception('Parameter $key must be a string.');
        }
        if (!is_int($fill)) {
            throw new \Exception('Parameter $fill must be an integer.');
        }
        if (preg_match("/^\d{2,}$/", $num) == 0) {
            throw new \Exception('Parameter $num must be a two or more Numbers.');
        }
        if (preg_match("/^\d{2,}$/", $key) == 0) {
            throw new \Exception('Parameter $key must be a two or more Numbers.');
        }
        if ($fill > 0 && strlen($num) < $fill) {
            $num = sprintf("%0{$fill}s", $num);
        }
        return join("", $this->numberDiffusion(str_split($num), str_split($key)));
    }
    function numberDecrypt($num, $key)
    {
        if (!is_string($num)) {
            throw new \Exception('Parameter $num must be a string.');
        }
        if (!is_string($key)) {
            throw new \Exception('Parameter $key must be a string.');
        }
        if (preg_match("/^\d{2,}$/", $num) == 0) {
            throw new \Exception('Parameter $num must be a two or more Numbers.');
        }
        if (preg_match("/^\d{2,}$/", $key) == 0) {
            throw new \Exception('Parameter $key must be a two or more Numbers.');
        }
        return join("", $this->numberRecovery(str_split($num), str_split($key)));
    }
    function generateKey()
    {
        if(!function_exists('openssl_pkey_new'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $configargs = array(
            'digest_alg' => 'sha256', 
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        );
        $res = openssl_pkey_new($configargs);
        openssl_pkey_export($res, $privKey, null);
        $details = openssl_pkey_get_details($res);
        return [
            'private' => $privKey,
            'public' => $details['key'],
        ];
    }
    function extractPubKey($privateKey, $passPhrase=null)
    {
        if(!function_exists('openssl_pkey_get_private'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $privRes = openssl_pkey_get_private($privateKey, $passPhrase);
        if (!is_resource($privRes)) {
            throw new \Exception('Invalid private key.');
        }
        $details = openssl_pkey_get_details($privRes);
        return $details['key'];
    }
    function setKey($privateKey, $passPhrase=null)
    {
        $this->publicKey = $this->extractPubKey($privateKey, $passPhrase);
        $this->privateKey = $privateKey;
        $this->passPhrase = $passPhrase;
    }
    function rsaPrivEncrypt($data)
    {
        if(!function_exists('openssl_private_encrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $pk = openssl_pkey_get_private($this->privateKey, $this->passPhrase);
        if (!is_resource($pk)) {
            throw new \Exception('Invalid private key.');
        }
        $result = openssl_private_encrypt($data, $encrypted, $pk);
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    function rsaPubDecrypt($data)
    {
        if(!function_exists('openssl_public_decrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $pk = openssl_pkey_get_public($this->publicKey);
        if (!is_resource($pk)) {
            throw new \Exception('Invalid public key.');
        }
        $result = openssl_public_decrypt(base64_decode($data), $​decrypted, $pk);
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
    function rsaPubEncrypt($data)
    {
        if(!function_exists('openssl_public_encrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $pk = openssl_pkey_get_public($this->publicKey);
        if (!is_resource($pk)) {
            throw new \Exception('Invalid public key.');
        }
        $result = openssl_public_encrypt($data, $encrypted, $pk);
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    function rsaPrivDecrypt($data)
    {
        if(!function_exists('openssl_private_decrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $pk = openssl_pkey_get_private($this->privateKey, $this->passPhrase);
        if (!is_resource($pk)) {
            throw new \Exception('Invalid private key.');
        }
        $result = openssl_private_decrypt(base64_decode($data), $​decrypted, $pk);
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
}
