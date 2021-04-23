<!--
 * @Author: your name
 * @Date: 2021-04-23 22:24:39
 * @LastEditTime: 2021-04-23 22:24:40
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: /crypto/README.md
-->
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

更多使用示例参看sample/index.php

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
