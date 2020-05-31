# Python chat

## Introduction
A basic example of a chat application which supports groups up to 10 people for each room. The goals of this project was to gain knowledge and experience in implementing encryption, diffie-hellman key exchange, digital signatures and SSL certificates into an Python application. This application is NOT(!!!!) meant for production or the sending of any sensitive data, therefore the GUI is ugly and very simplified and some huge security details are overlooked, see security issues for details.

Some security features/measures is:

* End-to-end encrypted message between clients using Fernet, which is a method that builds upon AES-128-CBC mode and a SHA256 hash authentication code (HMAC).

* Elliptic curve diffie-hellman (ECDH) key exchange. I've implemented ECDH so that it works for more than two clients. Further explaination below.

* SSL socket between clients and server, where server acts as both server and CA.

* Digital signatures using elliptical curves.

## ECDH
The client that creates the chatroom is elected "key hub". The key hub is responsible for creating a Fernet key which will be used by all parties. Each client that now connects to the chat room does a key exchange with the key hub using elliptic curve diffie-hellman to negotiate a shared key. The shared key is then used by the hub to encrypt the Fernet key by using AES-CBC mode. The client then decrypts the Fernet key by using the shared key. Both parties now shares the same Fernet key and can exchange messages without any interception. 

If the key hub exits the chat a new hub is elected, and no further action is needed as the new key hub already has the Fernet key.

## Security issues
Those that I know of:
* When a server verifies a client the client first sends it public key to the server. This is obviously wrong. A solution would be a login/register for clients which would generate a public key put in a database that the server would check with each challenge.
* The SSL certificate verification from the client has a callback function that is not implemented. Further research is essential for this to be OK.

## Usage
Before connecting to a server the user has to create a password. This password is for encrypting the PEM encoded elliptic curve private key used in digital signatures.
When first connecting to the server a menu is presented with several choices. Here you can choose between creating a new chat room, joining a chat room by name and getting a list of all chat rooms currently active.

The rest of the implementation details is commented in the code.


## Snapshots
![img](https://imgur.com/c6T6RRv.png)

![img](https://imgur.com/b1kyk2j.png)

![img](https://imgur.com/3EPV8ko.png)

![img](https://imgur.com/DYFmOl3.png)

As mentioned earlier. The GUI could be alot better. But that was not the focus of this project.

