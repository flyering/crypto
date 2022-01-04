<?php

namespace wpfly;

class Crypto
{
    /**************** RSA加密/解密 - 开始 ****************/
    protected $config = [
        'digest_alg' => 'sha256',
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ];
    protected $passPhrase = null;
    protected $privateKey = <<<PK
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
    protected $publicKey = <<<PK
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
    protected $privKeyRes = null;
    protected $pubKeyRes = null;

    protected $numberMap = [7, 3, 5, 8, 4, 0, 2, 1, 9, 6];
    protected $byteMap = [13, 10, 1, 7, 2, 14, 6, 9, 4, 0, 12, 8, 11, 3, 5, 15];

    /**
     * 配置OpenSSL。
     * @param array $config OpenSSL配置选项。
     * @return void
     */
    public function setConfig($config)
    {
        if (is_array($config)) {
            $this->config = array_merge($this->config, $config);
        }
    }
    /**
     * 生成RSA的公钥和私钥。
     * @param string $passPhrase 私钥密码。
     * @return array 公钥和私钥。
     */
    public function generateKey($passPhrase = null)
    {
        if (!function_exists('openssl_pkey_new')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $res = openssl_pkey_new($this->config);
        if (!$res) {
            throw new \Exception('Failure to generate the key.');
        }
        openssl_pkey_export($res, $privKey, empty($passPhrase) ? null : $passPhrase);
        $details = openssl_pkey_get_details($res);
        return [
            'private' => $privKey,
            'public' => $details['key'],
        ];
    }
    /**
     * 生成RSA的公钥和私钥并保存到文件。
     * @param string $filePath 要保存到的目录，文件名自动生成，可通过返回值获取到。
     * @param string $passPhrase 私钥密码。
     * @return array 公钥与私钥的文件名。
     */
    public function generateKeyToFile($filePath = '.', $passPhrase = null)
    {
        $filePath = rtrim(rtrim($filePath, '/'), '\\');
        if (!is_dir($filePath)) {
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
     * 从私钥中解析出公钥。
     * @param string $privateKey 私钥。
     * @param string $passPhrase 私钥密码。
     * @return string 公钥。
     */
    public function extractPubKey($privateKey, $passPhrase = null)
    {
        if (!function_exists('openssl_pkey_get_private')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $privRes = openssl_pkey_get_private($privateKey, $passPhrase);
        if (!is_resource($privRes)) {
            throw new \Exception('Invalid private key.');
        }
        $details = openssl_pkey_get_details($privRes);
        return $details['key'];
    }
    /**
     * 设置加密/解密使用的公钥。
     * @param string $publicKey 公钥。
     * @return void
     */
    public function setPublicKey($publicKey)
    {
        if (empty($publicKey)) {
            throw new \Exception('Parameter $publicKey cannot be empty.');
        }
        $this->publicKey = $publicKey;
        unset($this->pubKeyRes);
        $this->getPublicKey();
    }
    /**
     * 设置加密/解密使用的私钥。
     * @param string $privateKey 私钥。
     * @param string $passPhrase 私钥密码。
     * @return void
     */
    public function setPrivateKey($privateKey, $passPhrase = null)
    {
        if (empty($privateKey)) {
            throw new \Exception('Parameter $privateKey cannot be empty.');
        }
        $this->privateKey = $privateKey;
        $this->passPhrase = $passPhrase;
        unset($this->privKeyRes);
        $this->getPrivateKey();
        $this->setPublicKey($this->extractPubKey($privateKey, $passPhrase));
    }
    /**
     * 从文件加载加密/解密使用的公钥。
     * @param string $fileName 公钥文件名，需指定路径。
     * @return void
     */
    public function setPublicKeyFromFile($fileName)
    {
        if (!is_file($fileName)) {
            throw new \Exception('Public key file not found.');
        }
        $this->setPublicKey(file_get_contents($fileName));
    }
    /**
     * 从文件加载加密/解密使用的私钥。
     * @param string $fileName 私钥文件名，需指定路径。
     * @param string $passPhrase 私钥密码。
     * @return void
     */
    public function setPrivateKeyFromFile($fileName, $passPhrase = null)
    {
        if (!is_file($fileName)) {
            throw new \Exception('Private key file not found.');
        }
        $this->setPrivateKey(file_get_contents($fileName), $passPhrase);
    }
    /**
     * 处理公钥，使成为可使用的公钥资源。
     * @return resource 公钥资源。
     */
    protected function getPublicKey()
    {
        if (empty($this->pubKeyRes)) {
            if (!function_exists('openssl_pkey_get_public')) {
                throw new \Exception('OpenSSL functions are not available.');
            }
            $this->pubKeyRes = openssl_pkey_get_public($this->publicKey);
            if (!is_resource($this->pubKeyRes)) {
                throw new \Exception('Invalid public key.');
            }
        }
        return $this->pubKeyRes;
    }
    /**
     * 处理私钥，使成为可使用的私钥资源。
     * @return resource 私钥资源。
     */
    protected function getPrivateKey()
    {
        if (empty($this->privKeyRes)) {
            if (!function_exists('openssl_pkey_get_private')) {
                throw new \Exception('OpenSSL functions are not available.');
            }
            $this->privKeyRes = openssl_pkey_get_private($this->privateKey, $this->passPhrase);
            if (!is_resource($this->privKeyRes)) {
                throw new \Exception('Invalid private key.');
            }
        }
        return $this->privKeyRes;
    }
    /**
     * 私钥加密。
     * @param string $data 要加密的数据。
     * @return string 加密后的数据。
     */
    public function privEncrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if (!function_exists('openssl_private_encrypt')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $result = openssl_private_encrypt($data, $encrypted, $this->getPrivateKey());
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    /**
     * 公钥解密。
     * @param string $data 要解密的数据。
     * @return string 解密后的数据。
     */
    public function pubDecrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if (!function_exists('openssl_public_decrypt')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $result = openssl_public_decrypt(base64_decode($data), $​decrypted, $this->getPublicKey());
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
    /**
     * 公钥加密。
     * @param string $data 要加密的数据。
     * @return string 加密后的数据。
     */
    public function pubEncrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if (!function_exists('openssl_public_encrypt')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $result = openssl_public_encrypt($data, $encrypted, $this->getPublicKey());
        if (!$result) {
            throw new \Exception('Encryption failed.');
        }
        return base64_encode($encrypted);
    }
    /**
     * 私钥解密。
     * @param string $data 要解密的数据。
     * @return string 解密后的数据。
     */
    public function privDecrypt($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if (!function_exists('openssl_private_decrypt')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $result = openssl_private_decrypt(base64_decode($data), $​decrypted, $this->getPrivateKey());
        if (!$result) {
            throw new \Exception('Decryption failed.');
        }
        return $​decrypted;
    }
    /**
     * 私钥签名。
     * @param string $data 要签名的数据。
     * @return string 签名后的数据。
     */
    public function privSign($data)
    {
        if (!is_string($data)) {
            throw new \Exception('Parameter $data must be a string.');
        }
        if (!function_exists('openssl_sign')) {
            throw new \Exception('OpenSSL functions are not available.');
        }
        $result = openssl_sign($data, $signature, $this->getPrivateKey(), OPENSSL_ALGO_SHA1);
        if (!$result) {
            throw new \Exception('Sign failed.');
        }
        return base64_encode($signature . $data);
    }
    /**************** RSA加密/解密 - 结束 ****************/

    /**************** 扩散加密/解密 - 开始 ****************/
    /**
     * 计算扩散/还原轮数
     * @param int 明文或密文长度。
     * @return int 计算结果。
     */
    protected function calculateRound($len)
    {
        $round = 0;
        $x = $len - 1;
        while ($x > 0) {
            $round++;
            $x = ($x >> 1);
        }
        return $round;
    }
    /**
     * 生成数字加密/解密的S盒子。
     * @return string S盒子。
     */
    public function generateNumberMap()
    {
        $s = range(0, 9);
        shuffle($s);
        return "[" . implode(',', $s) . "]";
    }
    /**
     * 设置数字加密/解密使用的S盒子。
     * @param array $map S盒子。
     * @return void
     */
    public function setNumberMap($map)
    {
        $temp = $map;
        if (!is_array($temp)) {
            throw new \Exception('Parameter $map should be an array.');
        }
        sort($temp);
        if ($temp != range(0, 9)) {
            throw new \Exception('Parameter $map should be a permutation of 0 to 9.');
        }
        $this->numberMap = $map;
    }
    /**
     * 扩展数字加密/解密的密钥
     * @param string 要扩展的密钥。
     * @param int 扩展后的长度。
     * @return array 扩展后的密钥。
     */
    protected function extendNumKey($key, $len)
    {
        //通过多次哈希计算，然后利用进制转换，从而得到密码相关的且足够长的数字密码。
        $extKey = '';
        $i = 0;
        do {
            $aHex = str_split(md5($key . $i++), 8);
            $aNum = array_map(function ($item) {
                return substr(base_convert($item, 16, 10), 1);
            }, $aHex);
            $extKey .= join('', $aNum);
        } while (strlen($extKey) < $len);
        return str_split(substr($extKey, 0, $len));
    }
    /**
     * 数字加密。
     * @param string|int $numStr 要加密的数字。
     * @param string $key 密码，支持任意字符串。
     * @param int $fill 填充长度，填充0到要加密的数字前，使数字长度不小于填充长度。
     * @return string 加密后的数字字符串。
     */
    public function numberEncrypt($numStr, $key, $fill = 0)
    {
        $numStr = (string) $numStr;
        $fill = (int) $fill;
        if ($fill > 0 && strlen($numStr) < $fill) {
            $numStr = sprintf("%0{$fill}s", $numStr);
        }
        if (!preg_match("/^\d{2,}$/", $numStr)) {
            throw new \Exception('Parameter $numStr must be a two or more Numbers.');
        }
        $num = str_split($numStr);
        $numLen = count($num);
        //扩散轮数
        $round = $this->calculateRound($numLen);
        //每次扩散使用不同密码，所以需要扩展密码。
        $extLen = $numLen * $round;
        $extKey = $this->extendNumKey($key, $extLen);
        //扩散
        $z = 0;
        for ($i = 0; $i < $round; $i++) {
            for ($j = 0; $j < $numLen; $j++) {
                $dist = ($j + (1 << $i)) % $numLen;
                $num[$dist] = $this->numberMap[($num[$j] + $num[$dist] + $extKey[$z++]) % 10];
            }
        }
        return join('', $num);
    }
    /**
     * 数字解密。
     * @param string|int $numStr 要解密的数字。
     * @param string $key 密码，支持任意字符串。
     * @param int $fill 填充长度，填充0到要解密的数字前，使数字长度不小于填充长度。
     * @return string 解密后的数字字符串。
     */
    public function numberDecrypt($numStr, $key, $fill = 0)
    {
        $numStr = (string) $numStr;
        $fill = (int) $fill;
        if ($fill > 0 && strlen($numStr) < $fill) {
            $numStr = sprintf("%0{$fill}s", $numStr);
        }
        if (!preg_match("/^\d{2,}$/", $numStr)) {
            throw new \Exception('Parameter $numStr must be a two or more Numbers.');
        }
        $num = str_split($numStr);
        $numLen = count($num);
        //还原轮数
        $round = $this->calculateRound($numLen);
        //扩展密码
        $extLen = $numLen * $round;
        $extKey = $this->extendNumKey($key, $extLen);
        //还原
        $flippedMap = array_flip($this->numberMap);
        $z = $extLen;
        for ($i = $round - 1; $i >= 0; $i--) {
            for ($j = $numLen - 1; $j >= 0; $j--) {
                $dist = ($j + (1 << $i)) % $numLen;
                $num[$dist] = (20 + $flippedMap[$num[$dist]] - $num[$j] - $extKey[--$z]) % 10;
            }
        }
        return join("", $num);
    }
    /**
     * 生成字节加密/解密的S盒子。
     * @return string S盒子。
     */
    public function generateByteMap()
    {
        $s = range(0, 15);
        shuffle($s);
        return "[" . implode(',', $s) . "]";
    }
    /**
     * 设置字节加密/解密使用的S盒子。
     * @param array $map S盒子。
     * @return void
     */
    public function setByteMap($map)
    {
        $temp = $map;
        if (!is_array($temp)) {
            throw new \Exception('Parameter $map should be an array.');
        }
        sort($temp);
        if ($temp != range(0, 15)) {
            throw new \Exception('Parameter $map should be a permutation of 0 to 15.');
        }
        $this->byteMap = $map;
    }
    /**
     * 扩展字节加密/解密的密钥
     * @param string 要扩展的密钥。
     * @param int 扩展后的长度。
     * @return array 扩展后的密钥。
     */
    protected function extendByteKey($key, $len)
    {
        //通过多次哈希计算，从而得到密码相关的且足够长的字节密码。
        $extKey = '';
        $i = 0;
        do {
            $extKey .= md5($key . $i++);
        } while (strlen($extKey) < $len);
        return array_map('hexdec', str_split(substr($extKey, 0, $len)));
    }
    /**
     * 字节加密。
     * @param string $bytes 要加密的数据
     * @param string $key 密码，支持任意字符串。
     * @param bool $raw 加密后的数据格式，，true（默认）：原始数据，false：base64字符串
     * @return string 加密后的数据。
     */
    public function byteEncrypt($bytes, $key, $raw = true)
    {
        $bytes = (string) $bytes;
        if (empty($bytes)) {
            throw new \Exception('Parameter $bytes cannot be empty.');
        }
        $byteArray = array_map('hexdec', str_split(bin2hex($bytes)));
        $byteLen = count($byteArray);
        //扩散轮数
        $round = $this->calculateRound($byteLen);
        //每次扩散使用不同密码，所以需要扩展密码。
        $extLen = $byteLen * $round;
        $extKey = $this->extendByteKey($key, $extLen);
        //扩散
        $z = 0;
        for ($i = 0; $i < $round; $i++) {
            for ($j = 0; $j < $byteLen; $j++) {
                $dist = ($j + (1 << $i)) % $byteLen;
                $byteArray[$dist] = $this->byteMap[($byteArray[$j] + $byteArray[$dist] + $extKey[$z++]) % 16];
            }
        }
        $result = hex2bin(join("", array_map('dechex', $byteArray)));
        return $raw ? $result : base64_encode($result);
    }
    /**
     * 字节解密。
     * @param string $bytes 要解密的数据
     * @param string $key 密码，支持任意字符串。
     * @param bool $raw 解密前的数据格式，true（默认）：原始数据，false：base64字符串
     * @return string 解密后的数据。
     */
    public function byteDecrypt($bytes, $key, $raw = true)
    {
        $bytes = (string) $bytes;
        if (empty($bytes)) {
            throw new \Exception('Parameter $bytes cannot be empty.');
        }
        $byteArray = array_map('hexdec', str_split(bin2hex($raw ? $bytes : base64_decode($bytes))));
        $byteLen = count($byteArray);
        //还原轮数
        $round = $this->calculateRound($byteLen);
        //扩展密码
        $extLen = $byteLen * $round;
        $extKey = $this->extendByteKey($key, $extLen);
        //还原
        $flippedMap = array_flip($this->byteMap);
        $z = $extLen;
        for ($i = $round - 1; $i >= 0; $i--) {
            for ($j = $byteLen - 1; $j >= 0; $j--) {
                $dist = ($j + (1 << $i)) % $byteLen;
                $byteArray[$dist] = (32 + $flippedMap[$byteArray[$dist]] - $byteArray[$j] - $extKey[--$z]) % 16;
            }
        }
        return hex2bin(join("", array_map('dechex', $byteArray)));
    }
    /**************** 扩散加密/解密 - 结束 ****************/

    /**************** AES加密/解密 - 开始 ****************/
    /**
     * AES加密。
     * @param string $plaintext 要加密的数据。
     * @param string $key 密码。
     * @param bool $raw 加密后的数据格式，，true：原始数据，false（默认）：base64字符串
     * @return string 加密后的数据。
     */
    public function aesEncrypt($plaintext, $key, $raw = false)
    {
        $cipher = "aes-128-cbc";
        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha1', $iv . $ciphertext_raw, $key, true);
        return $raw ? ($hmac . $iv . $ciphertext_raw) : base64_encode($hmac . $iv . $ciphertext_raw);
    }
    /**
     * AES解密。
     * @param string $ciphertext 要解密的数据。
     * @param string $key 密码。
     * @param bool $raw 解密前的数据格式，true：原始数据，false（默认）：base64字符串
     * @return string 解密后的数据。
     */
    public function aesDecrypt($ciphertext, $key, $raw = false)
    {
        $cipher = "aes-128-cbc";
        $ivlen = openssl_cipher_iv_length($cipher);
        $c = $raw ? $ciphertext : base64_decode($ciphertext);
        $hmaclen = 20;
        if (strlen($c) <= $hmaclen + $ivlen) {
            throw new \Exception('Ciphertext is cut.');
        }
        $hmac = substr($c, 0, $hmaclen);
        $iv = substr($c, $hmaclen, $ivlen);
        $ciphertext_raw = substr($c, $ivlen + $hmaclen);
        if (strcmp($hmac, hash_hmac('sha1', $iv . $ciphertext_raw, $key, true)) != 0) {
            throw new \Exception('Ciphertext is modified.');
        }
        $result = openssl_decrypt($ciphertext_raw, $cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
            throw new \Exception('Decryption failed.');
        }
        return $result;
    }
    /**************** AES加密/解密 - 结束 ****************/
}
