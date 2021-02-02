<?php
require '../src/Crypto.php';

use wpfly\Crypto;

$crypto = new Crypto();
var_dump($crypto->generateMap());
$crypto->setMap([2,9,8,5,3,6,4,1,7,0]);

$num = '12';
$key = '639';
$r1 = $crypto->numberEncrypt($num, $key, 10);
$r2 = $crypto->numberDecrypt($r1, $key);
var_dump($r1, $r2);

$k1 = $crypto->generateKey();
var_dump($k1);

$pk = <<<PK
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDD+rp43CV0EnEL
gkI8GHsRkmgUTY4igkQ488Gyd7yngk91zDfcx+d+YlV5OVMjUImb8hLU/XGqyatI
pW28ZfIBeyO7ZakXCCWkhOWljr0EqT4L9SDJF6IJI/+pPqjW3VSQnePIkaR5q08o
SVaoja5usd/xOdVbTDB4yomf9ufzip4fEj4rCD3VKKdePFJBbHVXhI3W7NqbFtxE
iDfiSIYB8bF6SgIzzC90Ia4ze/8iOdrKDpVm5/kNPgKf8gbxf26CEgrLrl6KtNXr
wBLWQ0i5FMgljPRSqjrSFAjPH+Zg1HRCDWmekXrcm1Ihx022nQqo06zdvwnlILnn
m22WntpBAgMBAAECggEAYxwOZ4a1rjCRWMekJW4f9u/6kKH0CoGkbMThJRcmofPl
qWYArjeuW5zxKuARql9VaDcQzQPrEvrwE0oN5+QKcjNLC79KtuoY102aMZKxBoVs
anGqBehcupCo/3c/vYGq/YPLqSf2bM10t6P3HkCggTyVSxH7UzOBo+SRmwMrpF6H
ykJeTP0fUF2ALu3IoOX9zE14qQETwbWfTrDkb8npi3zkG4vzrF+vdHf3ByCIQwTb
Bx4+P54T+42xT2Yn5bVmjoRchxWywev9D79wG+QjRTHu1PAkPtgxlR2Gd7apo4oE
cILOtGRFA0BBzN9tMrODhWSHTyE5Jo7XiLYza3alAQKBgQDtwKd8nGn0grKEbuWU
5wSegWKRlBKY2QfRyqp+bMM93xsfOWbKV25Rx6PeLUfa6mLur3bThwzgtms3tJTr
L20ueVNcgWp6UzVRFQEZPNv3PlQ4/sO434Lp/OokybM2CiKQqt55tIZlOMtZhBzo
uwCSDjxEkmCOHBKWTGmWkhhQkQKBgQDTBVF4g+Tb9eG8mkf/bXbDt48E5pcVCYD4
qW36lV1KoLzaaJ6yK2OjG8L8YBWyoYMZlWdqw1f5SItGtoEJ5qh3aqf+qec/8YcE
5hkAI5X+aXLYxVy1Bv9NNSprTpoKw2AtBvrp5UcZAuTfR6H9dqKgIPuVZ+PceDzs
W/GsvQ/GsQKBgQDmwS3ODCHqZ0/MqbW6J96b2QhKM2U5ZKvqOsHvorB8xKYWUCgs
C1/Pj+zEHz62gvcyoqq580HUeDjoACTpf0aA7NCz4AfwYgJFiBVg4Wi9N4mXJ+3e
6VCuugKnYfzGXl/d+XmktkoaxFzZrRhB6f5Lw/VKuKduRmDj75YrxfBDgQKBgQCX
kNpTlWhsFM9uh+HutND5An7XJkid85WPBSLZOS8oywraVQqnLkMChI4od1seUqO3
XHhLVsN5aYGf6LYGRoX6P8EqSR6v7urrudl7IBQ8B8FVsWxFGiGFcwpkyLAbyvjp
XnoaRXQrosiBFxJi2zMzkH0jcttXH4Wivud3CtSqAQKBgQDn2A/j85+ng8HJFxBC
XIxH+sJPszxSchWKEOJwZqrSjYMZXdiJK5Wg4BAlTAk+OmWYFEQeWp7t9mUvU0rY
RTIASXyKiSJf/volnJb2r4/Y2PSQjfyadVdMiwhbBhq0QHV05uD3vwhpeDcZERa2
vWezTU1t4kXR8Ln3AU7tVrcM9g==
-----END PRIVATE KEY-----
PK;
$k2 = $crypto->extractPubKey($pk, '');
var_dump($k2);

$s = 'sfsgdfhfhfd';
$d1 = $crypto->rsaPrivEncrypt($s);
$d2 = $crypto->rsaPubDecrypt($d1);
$d3 = $crypto->rsaPubEncrypt($s);
$d4 = $crypto->rsaPrivDecrypt($d3);
var_dump($d1, $d2, $d3, $d4);

