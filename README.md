**http(s) express security examples**

Design Choices

 Security examples. 
 
 This code consists of an http(s) server and several express middlewares that:
 
  1) check white list accept request
  
  2) prevent ddos attack creating a limit x request saved in memory(can use redis) 
  
  3) generate a ttl token asking a server token
  
 The purpose of this code is learn how to do this 

(c) Nacho Ariza 2018