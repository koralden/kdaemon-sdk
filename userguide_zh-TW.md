# 這是什麼

[珊瑚空間計畫](https://koralden.org/)

# 架構

TBD

# 安裝
可以下載或自行編譯

## 下載
直接下載最新已編譯二進制檔並解壓縮到預設目錄  
```sh
curl -s https://github.com/koralden/kdaemon-sdk/releases/download/v0.0.8-rpi/kdaemon-0.0.8-rpi.tar.gz | sudo tar xvfz -C /
```


## 自行編譯

請先安裝[Rust Toolchain](https://rustup.rs)

```sh
git clone https://github.com/koralden/kdaemon-sdk
cd kdaemon-sdk
make
sudo make install
```

# 開始使用

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



## 綁定
需搭配手機[K-APP](https://apps.apple.com/tw/app/koralden-k-app-%E7%A4%BE%E7%BE%A4%E7%89%88/id1642699129)完成綁定

首先，先在RPi4執行如下命令
```sh
fika-easy-setup -a 0.0.0.0
```

[![asciicast](https://asciinema.org/a/IRTbosy4u0YD9gJxItbabNcri.svg)](https://asciinema.org/a/IRTbosy4u0YD9gJxItbabNcri)  

請記得先完成開通程序，否則easy-setup daemon執行會有(類似)如下錯誤
![image](https://user-images.githubusercontent.com/6879607/203676004-cafafec9-d272-4321-a721-090fec51102b.png)

接著由筆電(或電腦)瀏覽器打開[pairing網址](https://raspberrypi:8888)
![image](https://user-images.githubusercontent.com/6879607/203688941-cf725cd6-d06e-48f4-8e76-723dd3f61e08.png)


打開手機K-APP掃描此QR-CODE完成綁機程序  
(登入)  
![image](https://user-images.githubusercontent.com/6879607/203730533-90173e56-706b-4531-94cc-4f7582530f0e.png)
   

(按地圖右上方 **+** 進入綁定)  

![image](https://user-images.githubusercontent.com/6879607/203730825-7b78c845-3f24-436d-9156-b2b6a1028a5e.png)
  
(選擇右方QR CODE掃描)  
  
![image](https://user-images.githubusercontent.com/6879607/203731071-7d3b85a5-4745-4683-9d38-1146b854edf4.png)
  
  
(對準瀏覽器中的QR code)  
  
 tbd
  
(完成)  
  
![image](https://user-images.githubusercontent.com/6879607/203731868-b1824619-b1ae-4186-9d15-3a81698d49ad.png)  
  
  

  
綁定成功後，瀏覽器重新刷新(refresh)會發現由QR-code換成如下已綁定資訊(以避免重覆綁定)
  
![image](https://user-images.githubusercontent.com/6879607/203734693-f0bbe1eb-4523-4c9a-8e41-f3b05d8ed573.png)

## 最後

重新執行fika-manager daemon即可
```sh
killall -KILL fika-manager
fika-manager daemon
```

你可以使用systemd/service將fika-manager放到背景執行並在重新開機後主動呼叫  




# 問題排除
* *kdaemon-sdk沒辦法寫入設定檔及其路徑!*  
 **SDK預設寫入/userdata目錄，請設為writable**
 ```sh
 sudo chown -R pi:pi /userdata
 chmod -R 750 /userdata
 ```
* *RPi4 FW重新刷寫後，所有設定皆被清除*  
 **使用者需自行備份/userdata下所有設定，否則需重新執行設備開通流程**

* *K-APP登入所使用的錢包從哪裡來?*  
 **請使用第三方有公信力錢包，如[metamask](https://metamask.io/)，並完成[K-APP註冊流程](https://koralden.org/k-app/userguide)**
 
* *綁定時一直出現「opcode不存在」錯誤*  
 **Opcode每5分鐘過期，請手動重新刷新pairing網頁**

