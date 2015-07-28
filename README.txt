Juan C. Riano



Encription
==========

The encription algorithm performs:
ciphertext = negIP ( Fk2 ( SW ( Fk1 ( IP ))))

How to compile:
$> make

How to run sender:
$> ./sender <my port> <receiver address> <receiver port> <source file name> <window size>
example: $> ./sender 3010 localhost 3040  matrix.png 20

How to terminate the server (in Linux):
$> ctrl-c

How to run receiver:
$> ./receiver <my port> <destionation name>
example: $> ./receiver 3040 mifile11.png

How to terminate the client:
$> quit



LIMITATIONS AND BUGS
====================

- Check sum not implemented
- Destination file gests some garble, could not debug it. Text files are
  mostly readable when they arrive at the other side.
- Could not get it to work with the twister.

NOTE: I ran out of time, debugging took me too long. Sorry.


