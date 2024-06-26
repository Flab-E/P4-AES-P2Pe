
# Diffie-Hellman AES P4

A pure P4 implementation towards Diffie-Hellman key exchange with AES encryption.

# How to cite this work
dh-aes-p4 was presented in 2021 IEEE Conference on Network Function Virtualization and Software Defined Networks (NFV-SDN).
```bibtex
@INPROCEEDINGS{9665012,
  author={Oliveira, Isaac and Neto, Emídio and Immich, Roger and Fontes, Ramon and Neto, Augusto and Rodriguez, Fabrício and Rothenberg, Christian Esteve},
  booktitle={2021 IEEE Conference on Network Function Virtualization and Software Defined Networks (NFV-SDN)}, 
  title={dh-aes-p4: On-premise encryption and in-band key-exchange in P4 fully programmable data planes}, 
  year={2021},
  volume={},
  number={},
  pages={148-153},
  keywords={Conferences;Prototypes;Turning;Hazards;Encryption;Network function virtualization;Computational efficiency},
  doi={10.1109/NFV-SDN53031.2021.9665012}}
```
# Demo

[<img src="imgs/demo.png" width="700" height="400">](https://www.youtube.com/watch?v=vKngddt_brA)


# Features

* Diffie-Hellman key exchange;
* AES Encryption/Decryption;
* AES Key schedule;
* AES Key schedule validation in Python. Please visit [aestoolbox](https://github.com/emdneto/aestoolbox);

# Pre requisites

* [Mininet-wifi](https://github.com/intrig-unicamp/mininet-wifi) with P4 extensions;
* Python-pip. If you don't have [pip](https://pip.pypa.io) installed, this [Python installation guide](http://docs.python-guide.org/en/latest/starting/installation/) can guide you through the process.

# Preparing the environment & Running the dh-aes-p4 

All instructions on how to reproduce the results of this work can be found in the [README.md](./mininet/README.md) of mininet dir. 


# Disclaimer

This implementations should not be used in security softwares or production environments. The dh-aes-p4 is only for research purposes.

# License

GNU AFFERO GENERAL PUBLIC LICENSE

See LICENSE to see the full text.
