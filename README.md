<!--
 * @Author: your name
 * @Date: 2021-04-23 22:24:39
 * @LastEditTime: 2021-05-09 19:37:08
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /crypto/README.md
-->
# crypt

#### 介绍
常用加密/解密库，目前包括RSA加密/解密、整数加密/解密、AES加密/解密。

#### 安装方法

$ composer require uclbrt/api-sdk

#### 使用说明

use wpfly\Crypto;

<br>

//RSA加密、解密

//自带公钥私钥，以便“开箱即用”去试验，但实际使用中，请一定一定重新设置密钥后再加密！

$crypto = new Crypto();

$s = '我真是个天才！';

$d1 = $crypto->privEncrypt($s);

$d2 = $crypto->pubDecrypt($d1);

$d3 = $crypto->pubEncrypt($s);

$d4 = $crypto->privDecrypt($d3);

var_dump($s, $d1, $d2, $d3, $d4);

<br>

//数字加密、解密

$crypto = new Crypto();

$num = '12';

$key = '639';

$r1 = $crypto->numberEncrypt($num, $key, 10);

$r2 = $crypto->numberDecrypt($r1, $key);

var_dump($num, $r1, $r2);

<br>

//输出结果：

//string(2) "12"

//string(10) "1759624947"

//string(10) "0000000012"

<br>

//AES加密、解密

$crypto = new Crypto();

$s = '我真是个天才！';

$d1 = $crypto->aesEncrypt($s, 'password5');

$d2 = $crypto->aesDecrypt($d1, 'password5');

var_dump($s, $d1, $d2);

<br>

更多使用示例参看 sample/index.php

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
