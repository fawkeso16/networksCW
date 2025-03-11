Currently code runs 2 threads, sender and reciever. Data is sent encrypted with a encryption and authentication with diffie hellman key exchange

Very basic analysis:
  • socket 2 - 25% packet loss
  • socket 3 - packet loss+ packet shuffling
  • socket 4 - packet data being invalidated
