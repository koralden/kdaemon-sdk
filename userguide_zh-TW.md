# 這是什麼

[珊瑚空間計畫](https://koralden.org/)

# 架構

TBD

# 安裝

## 

# 好何使用

## 設備開通/激活
SSH連線進RPi4，執行如下命令
```sh
fika-manager activate
```



[![asciicast](https://asciinema.org/a/539698.svg)](https://asciinema.org/a/539698)

並將結果複製貼到[Discord社群](https://discord.com/channels/975795016410755082/1030338238600192000)

![image](https://user-images.githubusercontent.com/6879607/203516169-883e6166-4980-44a9-9e2c-7e5360be59a1.png)

平台管理員需依據提交的JSON內容設定後端並將結果回復到Discord，約一~二個工作天。

當收到Discord正面回覆後，執行如下命令
```sh
fika-manager daemon
```


[![asciicast](https://asciinema.org/a/539705.svg)](https://asciinema.org/a/539705)

若後端尚未設定，則會出現如下錯誤訊息
![image](https://user-images.githubusercontent.com/6879607/203674158-c5b61db8-227b-4993-8863-ae43cdea6fa8.png)


接下來執行
```sh
fika-easy-setup -a {eth0-IP-address}
```




## 綁定
需搭配手機[K-APP](https://apps.apple.com/tw/app/koralden-k-app-%E7%A4%BE%E7%BE%A4%E7%89%88/id1642699129)完成綁定

首先，先在RPi4執行如下命令
```sh
fika-easy-setup -a {eth0-IP-address}

```
請記得先完成開通程序，否則easy-setup daemon執行會有(類似)如下錯誤
![image](https://user-images.githubusercontent.com/6879607/203676004-cafafec9-d272-4321-a721-090fec51102b.png)

接下來用筆電或電腦的瀏覽器打開[pairing網址](https://raspberrypi:8888)
![image](https://user-images.githubusercontent.com/6879607/203688941-cf725cd6-d06e-48f4-8e76-723dd3f61e08.png)

最後再使用手機K-APP掃描此QR-CODE完成綁機程序
(登入)
tbd

(按地圖右上方+進入綁定)
tbd

(選擇右方QR CODE掃描)

(對準瀏覽器中的QR code)

(完成)

需事先完成錢包申請及註冊程序，詳情請見[K-APP-Userguide](http://todo)



![image](https://user-images.githubusercontent.com/6879607/203523539-41278ef0-939c-4578-aba5-5e3374e8c83e.png)



# 問題排除
## [Q] 沒辦法寫入預設設定檔及其路徑!
 SDK預設寫入/userdata目錄，請設為writable
 ```sh
 sudo chown -R pi:pi /userdata
 chmod -R 750 /userdata
 ```
## [Q] SD card重新刷寫後，所有設定皆被清除
 使用者需自行備份/userdata下所有設定，否則需重新執行設備開通流程

## [Q] K-APP登入所使用的錢包從哪裡來?
 請使用第三方有公信力錢包，如[metamask](https://metamask.io/)，並完成[K-APP註冊流程](https://koralden.org/k-app/userguide)
 
## [Q] 綁定時一直出現「opcode不存在」錯誤
 Opcode每5分鐘過期，請**手動refresh**pairing網頁

