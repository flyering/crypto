# crypt

#### 介绍
常用加密解密库，目前包括RSA加密/解密、整数加密\解密。

#### 安装方法

$ composer require uclbrt/api-sdk

#### 使用说明

use wpfly\Crypto;

function useCase1()
{
    $crypto = new Crypto();
    $num = '12';
    $key = '639';
    $r1 = $crypto->numberEncrypt($num, $key, 10);
    $r2 = $crypto->numberDecrypt($r1, $key);
    var_dump($num, $r1, $r2);
}

function useCase2()
{
    //自带公钥私钥，以便“开箱即用”去试验，但实际使用中，请一定一定重新设置密钥后再加密！
    $crypto = new Crypto();

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}

function useCase3()
{
    $crypto = new Crypto();
    var_dump($crypto->generateKey('password1'));
}

function useCase4()
{
    $crypto = new Crypto();
    $pk = <<<PK
-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----
PK;
    var_dump($crypto->extractPubKey($pk, 'password2'));
}

function useCase5()
{
    $crypto = new Crypto();

    //由于私钥中包含公钥，所以设置私钥后，私钥加密(签名)/公钥解密/公钥加密(保密传输)/私钥解密均可调用。
    $crypto->setPrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----', 'password3');

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}


function useCase6()
{
    $crypto = new Crypto();

    //只设置公钥，所以只能调用公钥加密/解密，如果此时调用私钥加密/解密，会使用自带私钥，此时加密/解密不对应，。
    $crypto->setPublicKey('-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----');

    $e = 'C2Jzf7L9iHUVb2T/P2Jm9lstF4R40W1QsV2I37bch5b89iDtBx/RxW6IssLovOCB5/B9ddUL7LAH0VPr6OF3a8sR2FEnr7CHzshFvQ0O7xgaekGZ/ZeMPrc0aFup/SWSkh9StUx9N32thgbie7N2Ml1zqZ/z7rpl0tXEXCswqneNowUnBsbarHTNBd+/4c7HhgiTm/oRcz7D3aFN59UVPLBbEQ9nAlBp9ARsmT4/0Se5me4kwEJTswtvRkcjx02SGyjjkcrX3ZUEazCtx+183YkgEIniMPnpsx2HxTnJdk8tbOz0YBPrLX3W1l1Il+sXP+I1lPtiCIDyXqpi8g1BjA==';
    $s = '我真是个天才！';

    $d1 = $crypto->pubDecrypt($e);
    $d2 = $crypto->pubEncrypt($s);

    var_dump($e, $s, $d1, $d2);
}


function useCase7()
{
    $crypto = new Crypto();

    $fileName = $crypto->generateKeyToFile('./', 'password4');
    $crypto->setPublicKeyFromFile($fileName['public']);
    $crypto->setPrivateKeyFromFile($fileName['private'], 'password4');

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}

ob_start();
try{
    echo "用例1：\r\n";
    useCase1();
    echo "\r\n";
    echo "用例2：\r\n";
    useCase2();
    echo "\r\n";
    echo "用例3：\r\n";
    useCase3();
    echo "\r\n";
    echo "用例4：\r\n";
    useCase4();
    echo "\r\n";
    echo "用例5：\r\n";
    useCase5();
    echo "\r\n";
    echo "用例6：\r\n";
    useCase6();
    echo "\r\n";
    echo "用例7：\r\n";
    useCase7();
    echo "\r\n";
}catch(Exception $e)
{
    echo $e->getMessage();
}
$out = ob_get_clean();
$out = str_replace("\r\n", "<br/>", $out);
$out = str_replace("\n", "<br/>", $out);
echo $out;

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
