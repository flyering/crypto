<?php

namespace wpfly;

class Crypto
{    
    /**************** RSA加密/解密 - 开始 ****************/
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
    private $privKeyRes = null;
    private $pubKeyRes = null;

    /**
     * @description: 
     * @param {*} $passPhrase
     * @return {*}
     */
    public function generateKey($passPhrase = null)
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
        openssl_pkey_export($res, $privKey, empty($passPhrase)?null:$passPhrase);
        $details = openssl_pkey_get_details($res);
        return [
            'private' => $privKey,
            'public' => $details['key'],
        ];
    }
    /**
     * @description: 
     * @param {*} $filePath
     * @param {*} $passPhrase
     * @return {*}
     */
    public function generateKeyToFile($filePath = '.', $passPhrase = null)
    {
        $filePath = rtrim(rtrim($filePath, '/'), '\\');
        if(!is_dir($filePath))
        {
            throw new \Exception('Parameter $filePath is not a valid folder.');
        }
        $key = $this->generateKey($passPhrase);
        $filePath .= DIRECTORY_SEPARATOR;
        $timestamp = time();
        $privateFileName = $filePath . 'private_' . $timestamp . '.key';
        $publicFileName = $filePath . 'public_' . $timestamp . '.key';
        file_put_contents($privateFileName, $key['private']);
        file_put_contents($publicFileName, $key['public']);
        return [
            'private' => $privateFileName,
            'public' => $publicFileName,
        ];
    }
    /**
     * @description: 
     * @param {*} $privateKey
     * @param {*} $passPhrase
     * @return {*}
     */
    public function extractPubKey($privateKey, $passPhrase = null)
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
    /**
     * @description: 
     * @param {*} $publicKey
     * @return {*}
     */
    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
        unset($this->pubKeyRes);
        $this->getPublicKey();
    }
    /**
     * @description: 
     * @param {*} $privateKey
     * @param {*} $passPhrase
     * @return {*}
     */
    public function setPrivateKey($privateKey, $passPhrase = null)
    {
        $this->privateKey = $privateKey;
        $this->passPhrase = $passPhrase;
        unset($this->privKeyRes);
        $this->getPrivateKey();
        $this->setPublicKey($this->extractPubKey($privateKey, $passPhrase));
    }
    /**
     * @description: 
     * @param {*} $fileName
     * @return {*}
     */
    public function setPublicKeyFromFile($fileName)
    {
        if(!is_file($fileName))
        {
            throw new \Exception('Public key file not found.');
        }
        $this->setPublicKey(file_get_contents($fileName));
    }
    /**
     * @description: 
     * @param {*} $fileName
     * @param {*} $passPhrase
     * @return {*}
     */
    public function setPrivateKeyFromFile($fileName, $passPhrase = null)
    {        
        if(!is_file($fileName))
        {
            throw new \Exception('Private key file not found.');
        }
        $this->setPrivateKey(file_get_contents($fileName), $passPhrase);
    }
    /**
     * @description: 
     * @param {*}
     * @return {*}
     */
    private function getPublicKey()
    {
        if(empty($this->pubKeyRes))
        {
            if(!function_exists('openssl_pkey_get_public'))
            {
                throw new \Exception('openssl functions are not available.');
            }
            $this->pubKeyRes = openssl_pkey_get_public($this->publicKey);
            if (!is_resource($this->pubKeyRes)) {
                throw new \Exception('Invalid public key.');
            }
        }
        return $this->pubKeyRes;
    }
    /**
     * @description: 
     * @param {*}
     * @return {*}
     */
    private function getPrivateKey()
    {
        if(empty($this->privKeyRes))
        {
            if(!function_exists('openssl_pkey_get_private'))
            {
                throw new \Exception('openssl functions are not available.');
            }
            $this->privKeyRes = openssl_pkey_get_private($this->privateKey, $this->passPhrase);
            if (!is_resource($this->privKeyRes)) {
                throw new \Exception('Invalid private key.');
            }
        }
        return $this->privKeyRes;
    }
    /**
     * @description: 
     * @param {*} $data
     * @return {*}
     */
    public function privEncrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if(!function_exists('openssl_private_encrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $result = openssl_private_encrypt($data, $encrypted, $this->getPrivateKey());
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    /**
     * @description: 
     * @param {*} $data
     * @return {*}
     */
    public function pubDecrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if(!function_exists('openssl_public_decrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $result = openssl_public_decrypt(base64_decode($data), $​decrypted, $this->getPublicKey());
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
    /**
     * @description: 
     * @param {*} $data
     * @return {*}
     */
    public function pubEncrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if(!function_exists('openssl_public_encrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $result = openssl_public_encrypt($data, $encrypted, $this->getPublicKey());
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    /**
     * @description: 
     * @param {*} $data
     * @return {*}
     */
    public function privDecrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if(!function_exists('openssl_private_decrypt'))
        {
            throw new \Exception('openssl functions are not available.');
        }
        $result = openssl_private_decrypt(base64_decode($data), $​decrypted, $this->getPrivateKey());
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
    /**************** RSA加密/解密 - 结束 ****************/

    /**************** 数字加密/解密 - 开始 ****************/
    /**
     * @description: 
     * @param {*} $m
     * @param {*} $p
     * @return {*}
     */
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
            $m[$mNext] = ($m[$mCurrent] + $m[$mNext] + $p[$pCurrent]) % 10;
            $m[$mCurrent] = ($m[$mPrev] + $m[$mCurrent] + $p[$pCurrent]) % 10;
        }
        return $m;
    }
    /**
     * @description: 
     * @param {*} $d
     * @param {*} $p
     * @return {*}
     */
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
            $d[$dCurrent] = ($d[$dCurrent] - $d[$dPrev] - $p[$pCurrent] + 20) % 10;
            $d[$dNext] = ($d[$dNext] - $d[$dCurrent] - $p[$pCurrent] + 20) % 10;
        }
        return $d;
    }
    /**
     * @description: 
     * @param {*} $num
     * @param {*} $key
     * @param {*} $fill
     * @return {*}
     */
    public function numberEncrypt($num, $key, $fill = 0)
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
    /**
     * @description: 
     * @param {*} $num
     * @param {*} $key
     * @return {*}
     */
    public function numberDecrypt($num, $key)
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
    /**************** 数字加密/解密 - 结束 ****************/
}