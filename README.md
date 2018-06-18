# iotAuth

## Protocol Operation

### Initial Handshake

- <strong> Step 1 </strong>

The first step starts with part A sending a packet to part B with the string "HELLO SERVER", in order to start the connection.

- <strong> Step 2 </strong>

Then part B responds with the string "HELLO ACK", and the connection is established.

### RSA Key Exchange

- <strong> Step 3 </strong>

In the third step, part A generates an asymmetric key pair (a public key and a private key), an Initialization Vector (IV), and an FDR (Challenge-Response Function). Then, this data, with the exception of the private key, is sent to part B.

- <strong> Step 4 </strong>

In this step, part B also generates its own pair of asymmetric keys, an IV and an FDR. This data is sent to part A (with the exception of the private key), along with the received FDR response.

### Diffie-Hellman Key Exchange

- <strong> Step 5 </strong>

In the fifth step, part A generates values for the Diffie-Hellman calculation: an exponent (a), a base (g) and a module (p).
This data, together with the FDR response from part B and the calculation result, are encapsulated in a packet. 
Now, a hash function is applied to this packet, and the result is encrypted with the private key of part A. 
Finally, the data packet and the hash are encapsulated in another packet, and the packet is encrypted with the public key of part B.

- <strong> Step 6 </strong>

In the sixth and last step, part B performs the Diffie-Hellman calculation from the information coming from part A.
As before, part B extracts the hash from the packet, encrypting it with its private key, and then encrypting the final packet with the public key of part A.

## Compiling and Running
- <strong> Server </strong>
```sh
$ ./server_compiler.sh
```
```sh
$ ./server
```

- <strong> Client </strong>
```sh
$ ./client_compiler.sh
```
```sh
$ ./client localhost
```
## Paper
[<strong>Autenticação mútua de nós sensores com nós intermediários para IoT no contexto de Fog Computing</strong>](http://www.sbrc2018.ufscar.br/wp-content/uploads/2018/04/09-181038__Autenticao_mutua_nos.pdf)
