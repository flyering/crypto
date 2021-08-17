<?php
require '../src/Crypto.php';

use wpfly\Crypto;

function useCase1()
{
    //自带公钥私钥，以便“开箱即用”去试验。实际中使用，请【一定】【一定】【一定】重新设置密钥后再加密（参考用例6）！
    $crypto = new Crypto();

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}

function useCase2()
{
    $crypto = new Crypto();
    $crypto->setConfig([
        'digest_alg' => 'sha256',
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
        //'config' => 'C:\\PHP\\extras\\openssl.conf', //Windows下生成密钥失败，尝试设置openssl.conf的正确路径
    ]);
    var_dump($crypto->generateKey('password1'));
}

function useCase3()
{
    $crypto = new Crypto();
    $pk = <<<PK
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI2LeuZlBMt3kCAggA
MBQGCCqGSIb3DQMHBAjhGc/91TbUmQSCBMjtxI+u5f8VeW18STYf8aS4eKryGFdd
JYovWKvjiZLbqKRthFck9FB8oLhDNuX/9HGmbzDFe0OFPE7tDqR+fidguVIEt5Yk
/LO8czyiBCj2DyMkDJ4oBfdmbOIJuryKy42+RkJ24PWyEc/lJVjaoLgoZbhCMd6f
ScnZJXrQCRedyL8AUfQpFbM4hAEKDe35Bye2VpzMaEha2Sy20Rogf0ctHP6zh+XT
GM8II7pruEOSosdhXoyefHxjBPn4MlDs30NcTCB0ELb8P/leeJXPo1fndpJivhpt
SZzCm0iNOWc/4Ytuc4dttccfSrqwuF6l3cmO/H3g286CVfUtwObJQCmOl2DhOKGj
1dgKxZ36auwViQFl6dsb61ory9w9fXb2T/k0uaH0wADkkol6I9qw1pH0f3NsTCSB
Z0cisy9hhOCbZNtdzwkhI8FWU8M1TSChAtAOhIgovNqaC5hCY8Nw2vFB8asb3Z4K
3cgb21zkgjRDz8mNIa4Ol3TjGs9zSMLflt7ofejCsiCY8cYFGr7TOpze3W+v12SH
RmdDtVdCvOGIaCBq05XwCUiKLi5ESBS+1VNMmbcAS7XNphsqghNL1vnkSrQbEQzA
UHm5fEUIJk5jQS/Z5T7P7s4ahfMLzFhAldMxmUAHjf4W/UeTCacuamaVgafl6/ow
Jrh/LnBsw67DBV4gRbfLrKNPtvnWtnbKbp210O7mTMuEbWol7A/iUEZxm02mb+kM
8tJ+vYn8S8W5yvC3XBCd23r2UG3yhvCz2pOXwQt/iR0wsWKmiLsGayEo+jzrnrip
QNTmxMzUL2eZVOVekz5RH7qFTkFeGPWp/Vb+F6J2HQG46cG0vaWfTFeHpAG5DGus
nqE/gkq8vjCYa6NUCsponWGyW4BHWbh5yU9KVRknmJq4dkevCJmn/lZnCTkMAkCG
iTDcXGscax8qUsw5DN61DDRQQMtwfATyv/0tMaoBRxVo3netSHshRtultPBzmD6m
4a/F5JK0bKGY798WVWNHjOIt0UHptb2DM2cN1Nout7wwZbcVqsJsUosbCSFOKF5U
hcCo3gF2kAxVBHnFstt561hMC1nlVy9Ih36CUpFRV3aLfBMHoVGZ5mwtYkllCTT2
oiFFUmliNc7lCf7eAMinLE/UI2rTgfOAMeuwt4ep8RnGpibb2XNReYHNDOxh7KKr
m6/0MIAKT38iK57wudcygjhE2ggJFHQaaxi0FDJiNIR9rwQDPCT8nR16XjVnEuc7
7PyokZVxk10EBjKmHnbZJCWEa5gZuTUnPtteLJgvOmDjOGYli0owvyw96XpiTdAL
1jATPMb1w4XcCmaTbm8GRhNSlBeQ1z/yVRSuiwb2wf9MsZM2kAy5Jq5nuAuaZLLi
mfVW64YAmTORPoolWWA9gSkVKOfwCUgeXBi6qm0tjQc017zJ9KwGnKVztdEWszdQ
Z4jlYRMrucM1l1j/Vo+iBlX6ojT/gmWUyiBygwd5Pem0t22z3L9j99l06jSBkr6K
dKVDZbbp+OgNMuHU4ymMoJaYBQVut4cueArURkF6cSu7VKEmHQ3MdZPG6/2/ywlQ
BmiiKCxk95zupRIxA853p2oX3a87pbVatr/TidyFXAz+JgRoPCPnPsSFCm624JPy
dAQ=
-----END ENCRYPTED PRIVATE KEY-----
PK;
    var_dump($crypto->extractPubKey($pk, 'password2'));
}

function useCase4()
{
    $crypto = new Crypto();

    //由于私钥中包含公钥，所以设置私钥后，私钥加密(签名)/公钥解密、公钥加密(保密传输)/私钥解密均可调用。
    $crypto->setPrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQITMP90bqVGf8CAggA
MBQGCCqGSIb3DQMHBAjXFimOAT0HIwSCBMgzQOTaGJTjSsIEcMKQ5h3nsSSBBQ7m
ilvF55Hcye1Kk/e+20CaCT7fD3jZmWcPL1msOXvmhI+aMJ5u/oSJcpJF7+DLZRGM
GLO+bzFBMnaJw+S03FYFY2s6P5fpmodob1lAUWuxexuNPGMViW8yh4FjUwTCyZS1
IgYTdxgZYj6Z4dpKvpejoHx47qy0KJgszzglHDEOZOc7QUB4NUZguEbji6vBdXVc
Bp+mlaCKhfI+Gr+sQqs6Akw+AfM2Mtd84Z5j+oRNuczgo5CoTjhfFT25rVx61IB6
U3Tf18QBQqzPwHRajhsZll4BRkVW1XeyXejDoXCucGeyoHjnpGhPLGY3w+dPxL12
6cqZb83QrATtzewfO4FzqGGdsLQojkGPrCEZ8pwX8PdxTZW2PXq0mvwT32o8SXom
vrAC2lQYJH2qdagWHvmkrxmTOy50xs1BI9nhHoM5vyIXmGjCrLMB5p5Xi3n/Mv6l
WCw2leQxNla+ADt6Lphc1cJNqOeCzwcXl3/fnXOVQkJHRJvbk1jNom5mV7NcSwWz
70yBBLuSK+RLprpBZnwkocd3kFCoLbo8qsasZJAt0D1JLi6jfsmNGBLxInbg2Fr4
KK/74wG8SoepnrLAuILOy9/yL2DESlS5pxDprFDU4IqwwFLRY7mAY176MoyTVTK6
p8wmtIEjt3urr2WpXUe1Q5hv1GxBVoPmvRUCjWfPx4bdvDhLSemUq1jsbsDufkNr
OUeKB5LjQIW/buioygmY+jXwOImNPGIE/kLp3yMXKgzprn9uA3cBG65RQYIL6n81
BHPhC3UnCNGvtJpARcqEw21SP4ry/hVwvYaYgRpnnrCx43OCykUe99KZiAdpEJqx
5syUNguchx6sbB3o/lnD2uJbcxB04UMlTu85mALe6aB3NbSawEWoogwn8SL9ONyt
4mvfQH1+2WusVtjAf5lh6HSWix/HESHzRDRz4K71fp9vXnO1p7dMnSjMJ+UauaWi
9DH6Y3YggrpnpGlf25y9lId1uoGy1NFg3jcKPeXD4tL5OAqL3+14SNkmORfJMhKM
JKZzof+dBEyw91TPw+gk/RWBhC+d9KyHBwsgdMTfUXXFuhfzHyhKHoJ4gsqdq6Xx
gaxBszx/C/dvEgwBrvVBGRJdj8xK+AuNzZp6hFcCI27CCAGwonYE/eeQUQ/d8jd6
J87lQ1W0NoVUNoiuLiWgsl3AcRqKQGKNh0PQFHzw11uADiOCBSDmYj49HT0xrh2w
q5hq4qe3yFuXcp2Ll6Kvx/ISNr9WiSfVMqKdCH1BBE1m5oAum/ofdXFNXYujGage
Eyc5RpIp1MISYVn9y1Cpq/xuocuvLfEaGptmeU8/A3ZiNvTUl3OhZ4LEiyp/flMh
rqJWzXPMeeZ3P/k3d44xYhajTD6CglxFX6XobJJ4y4gkIVF7pAb0dql6QfYaxyZa
bA0hN44Ua3DoxTaCZDaCZlp/PsnmXyrcY+JHZRPpY5kqDdoAlvCnHa9yMBNaeJKS
EzhXlXxVFLIom3pQrB/8EvntPH6bA/V0H9u6xXxdSqRP4SwIFgY25IP+/IPDWA92
WvVFKYquFo39BfIE2A0ZlEIbHMOlKBjJWE/YV4N9Ibqqy67ySQRSZgMEMrKnycBk
XM8=
-----END ENCRYPTED PRIVATE KEY-----', 'password3');

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}

function useCase5()
{
    $crypto = new Crypto();

    //只设置公钥，所以只能调用公钥加密/解密，如果此时调用私钥加密/解密，会使用默认的自带私钥，此时加密与解密不对应，。
    $crypto->setPublicKey('-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/w5nN+wVEccKKZo+IlB
uwzX23fYZcKGTSl9yToq1WlaQmR0Fmvgk2bpav2oJ7AWhnG94l2ZPUlASGk+8Q7l
UvezRXJ+zCENPjLFxV+45wsOPb08EA7X4/M+I0pnMqR47386D0gbHX8O27YfwY50
RaiPZqT/1zm1ZKfOmer2ZyrvgEGo4Q/8Fua4m77ymQ6R7CgHLtnudZNpBRCP89Zs
FG/WUGCXDUOk8DXPgtH3TGvsaWcstbkJZT3B7h1JBMm9+NjrDiXKXai0DsQ33I9v
EqYHvFipXVrmgalDs7YCyoEcgMw3i+o0JKzzapRAAfonXIWx37jQUjKpwpL8vJwd
cwIDAQAB
-----END PUBLIC KEY-----');

    $e = 'C2Jzf7L9iHUVb2T/P2Jm9lstF4R40W1QsV2I37bch5b89iDtBx/RxW6IssLovOCB5/B9ddUL7LAH0VPr6OF3a8sR2FEnr7CHzshFvQ0O7xgaekGZ/ZeMPrc0aFup/SWSkh9StUx9N32thgbie7N2Ml1zqZ/z7rpl0tXEXCswqneNowUnBsbarHTNBd+/4c7HhgiTm/oRcz7D3aFN59UVPLBbEQ9nAlBp9ARsmT4/0Se5me4kwEJTswtvRkcjx02SGyjjkcrX3ZUEazCtx+183YkgEIniMPnpsx2HxTnJdk8tbOz0YBPrLX3W1l1Il+sXP+I1lPtiCIDyXqpi8g1BjA==';
    $s = '我真是个天才！';

    $d1 = $crypto->pubDecrypt($e);
    $d2 = $crypto->pubEncrypt($s);

    var_dump($e, $s, $d1, $d2);
}

function useCase6()
{
    $crypto = new Crypto();

    $fileName = $crypto->generateKeyToFile('./', 'password4');
    //注意保证文件的读取权限
    $crypto->setPublicKeyFromFile($fileName['public']);
    $crypto->setPrivateKeyFromFile($fileName['private'], 'password4');

    $s = '我真是个天才！';

    $d1 = $crypto->privEncrypt($s);
    $d2 = $crypto->pubDecrypt($d1);

    $d3 = $crypto->pubEncrypt($s);
    $d4 = $crypto->privDecrypt($d3);

    var_dump($s, $d1, $d2, $d3, $d4);
}

function useCase7()
{
    $crypto = new Crypto();
    $num = '12';
    $key = 644;
    $r1 = $crypto->numberEncrypt($num, $key, 10);
    $r2 = $crypto->numberDecrypt($r1, $key);
    var_dump($num, $r1, $r2);
}

function useCase8()
{
    $crypto = new Crypto();

    $s = '我真是个天才！';

    $d1 = $crypto->aesEncrypt($s, 'password5');
    $d2 = $crypto->aesDecrypt($d1, 'password5');

    var_dump($s, $d1, $d2);
}

function useCase9()
{
    $crypto = new Crypto();

    $s = '我真是个天才！';

    $d1 = $crypto->privSign($s);

    var_dump($s, $d1);
}

function useCase10()
{
    $crypto = new Crypto();

    $s = '我真是个天才！';

    $d1 = $crypto->byteEncrypt($s, 'password6');
    $d2 = $crypto->byteDecrypt($d1, 'password6');

    $d3 = $crypto->byteEncrypt($s, 'password6', false);
    $d4 = $crypto->byteDecrypt($d3, 'password6', false);

    var_dump($s, $d1, $d2, $d3, $d4);
}

function useCase11()
{
    $crypto = new Crypto();

    $n = 66;

    $d1 = $crypto->byteEncrypt(pack('N', $n), 'password7', false);
    $d2 = unpack('N', $crypto->byteDecrypt($d1, 'password7', false));

    $d3 = $crypto->byteEncrypt(pack('J', $n), 'password7', false);
    $d4 = unpack('J', $crypto->byteDecrypt($d3, 'password7', false));

    var_dump($n, $d1, $d2, $d3, $d4);
}

ob_start();
try {
    $funs = get_defined_functions();
    foreach ($funs['user'] as $f) {
        if (!preg_match("/^usecase(\d+)$/", $f, $m)) {
            continue;
        }
        echo "用例{$m[1]}：\r\n\r\n";
        $f();
        echo "\r\n";
    }
} catch (Exception $e) {
    echo $e->getMessage();
}
$out = ob_get_clean();
$out = str_replace("\r\n", "<br/>", $out);
$out = str_replace("\n", "<br/>", $out);
header("Content-Type: text/html;charset=utf-8");
echo $out;
