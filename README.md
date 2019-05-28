# Forensic-Kiddie
Scripts that help in Forensic

## Windows Security Event
### Windows Security Event (WSE) Beautifier
![alt text](https://4.bp.blogspot.com/-xNPl57H6MaU/WrINUBW0GHI/AAAAAAAABN0/Zsix27PmqaIP4r53o-XJ4LMyiTIBN1YaACLcBGAs/s1600/wse_beautifier.PNG)

## Windows Command
### To check logs with an ID (e.g. 4624)
```
wevtutil qe security /f:text /q:*[System[(EventID=4624)]]
```
