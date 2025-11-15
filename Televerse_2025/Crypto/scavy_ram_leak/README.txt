Scavy's RAM Leak
 80
Bangladeshi student Scavy is hacking the StealthFlags CTF server from her dorm. While testing a buffer overflow, she accidentally leaked two RAM values: 0xc4115 and 0x4cf8. She quickly XOR'd them to create a secret key and sent it to her teammate.

Your job: find what Scavy did with these hex values to generate the final code. The answer must start with 0x.

Flag Format: CUETCTF{Xored_Value}


