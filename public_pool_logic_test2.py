import threading
import binascii
import hashlib
import socket
import random
import json
import struct
import time
import datetime
import pytz

address = "my_address"
difficulty = 0.0001
command = '{"id":1,"error":null,"result":[[["mining.notify","d136c4b9"]],"d136c4b9",4]}'
response = json.loads(command)
sub_details, extranonce1, extranonce2_size = response['result']
sub_details = sub_details[0][1]
print("sub_details", sub_details, "extranonce1:", extranonce1, "extranonce_int", int(extranonce1,16), "extranonce2_size", extranonce2_size)

params = ["dc8b3e","63a47ff11619185396e318932fa8b79488e9fb0d00031abc0000000000000000", \
"02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff190390950c5c7075626c69632d706f6f6c5c", \
"ffffffff02d849a62a000000001976a914f31210bee6f43fd8650ae072b64f33c93b1e4a4088ac0000000000000000266a24aa21a9ed4bd15048a7892d4e73e0109d067fe082a0ca4dc09ee2e4f01ee633c47f8b4cbd00000000", \
["747633e76283f74dacfad5a3c1e64708ece9755a25929b3e4cc09598c259f362", \
"3fdebaa19e37724e3f64830effa5446101e102492b8d6e48960f6dac768fa1f3", \
"e2834adaabf7f440a3dc9c3f0ec51b97d3c2c3efcfbc6f92090091be4f422415", \
"05741de13e07621745a82146649dcde050c2e5967d5b26f19d209037ef7509db", \
"806de683b06e6ad8efb30306b7cfd56641bd312215e32373ad1f426511d08516", \
"653db21e8e7aed77a218cf0aee75d3c12e67493401b198b0f55e9ae0c3b3596c", \
"cb98f9d9517c47b1d826fc78aad059e077c655b546c05807b8730a90944d5a5f", \
"fe1d97129dca4759ffec09e4b7203ac7f9033dddc350398cdbac83a78a6296b6", \
"1ea535780fd123fcabe7752da57a645de0e8cb7dfa875340ba2a19fb654c29bb", \
"7d512a42095a3bce1138ca012a5c4fc3546284cbfe1ebdd41e778665463dc65f", \
"6cf8d0d404f0e20c500c82774eb77a31ff578e4686fe699f8f6182f94cfda2c0", \
"0cbd1a37fe7f5005beb162989f43e84259e6151e9a9689edc39d4175ed1dc364"], \
"20000000","1703d869","659a5d31", "false"]

#for par in params:
#    print(par)
def rev(item):
    item = item[::-1]
    item = ''.join([item[i:i + 2][::-1] for i in range(0, len(item), 2)])
    return item
def rev8(item):
    item = item[::-1]
    item = ''.join([item[i:i + 8][::-1] for i in range(0, len(item), 8)])
    return item

def calc(params, extranonce1, nonce):
    job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = params

    target = (nbits[2:] + '00' * (int(nbits[:2], 16) - 3)).zfill(64)
    #extranonce2 = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(2 * extranonce2_size)  # create random
    extranonce2 = "00000001"
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    print("coinbase:", coinbase)
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    for h in merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()

    # little endian
    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])
    #merkle_root = rev(merkle_root)

    prevhash = rev8(prevhash)
    version_int = int(version, 16)
    time = int(ntime, 16)
    bits = int(nbits, 16)

    partial_header = struct.pack("<L", version_int) \
                     + bytes.fromhex(prevhash)[::-1] \
                     + bytes.fromhex(merkle_root)[::-1] \
                     + struct.pack("<LL", time, bits)

    nonce_int = int(nonce, 16)
    header = partial_header + struct.pack("<L", nonce_int)

    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    hash = binascii.hexlify(hash[::-1])

    print("target:", target)
    print("Version:    ", version)
    print("prevhash: ", prevhash)
    print("markle_root:", merkle_root)
    print("Time:", ntime)
    print("bits:", nbits)
    print("Hash:", hash)

    payload = bytes('{"params": ["' + address + '", "' + job_id + '", "' + extranonce2 + '", "' + ntime + '", "' + nonce + '"], "id": 1, "method": "mining.submit"}\n', 'utf-8')
    print(payload)

nonce = "1aa1787c"
calc(params, extranonce1, nonce)

def calc3(markle_root, prev_block, version, time, bits, nonce_input):
    version = int(version,16)
    partial_header = struct.pack("<L", version) \
                     + bytes.fromhex(prev_block)[::-1] \
                     + bytes.fromhex(markle_root)[::-1] \
                     + struct.pack("<LL", time, int(bits, 16))
    print("=========================out==========================")
    print("Version:    ", str(struct.pack("<L", version).hex()).zfill(64))
    print("prev_block: ", str(bytes.fromhex(prev_block)[::-1].hex()).zfill(64))
    print("markle_root:", str(bytes.fromhex(markle_root[::-1]).hex()).zfill(64))
    print("Time:", str(struct.pack("<L", time).hex()).zfill(64))
    print("bits:", str(struct.pack("<L", int(bits, 16)).hex()).zfill(64))

    nonce = int(nonce_input, 0)

    header = partial_header + struct.pack("<L", nonce)
    print("Partial header:", binascii.hexlify(partial_header))
    print("Header:        ", binascii.hexlify(header))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    print("Success:", nonce, binascii.hexlify(hash[::-1]))
    print("===================================================================================")

markle_root = "5b367a43b088482727037924a7716fa349e9830c0680df639f4a307ee1926f81"
prev_block = "00000000000000000000e9a9677918b43e2a6c84d6e6ccf00f3d9b48eae54576"
#version = 0x2b58c000
version = "2b58c000"
time_input = "2023-12-30 06:52:06" #time -3 hour for adjust gmt, 2023-12-30 09:52:06 GMT +3
date_time = datetime.datetime.strptime(time_input, "%Y-%m-%d %H:%M:%S")
timezone = pytz.timezone('Etc/GMT-0')
date_time = timezone.localize(date_time)
time = int(date_time.timestamp())
#time = "0x659a5d31"
nonce = "0x0699dc74"
bits = '0x1703e8b3'
#result: 000000000000000000015453335be3bd91a1634ac8c19d3bb38adcef2cdfba3b
#calc3(markle_root, prev_block, version, time, bits, nonce)



markle_root = "e62c1c96853f45e110a5b3911c22706a9aed8d0fac34e7441138bf7b46403d94"
prev_block = "000000000000000000031abc88e9fb0d2fa8b79496e318931619185363a47ff1"
version = "279ce000"
time_input = "2024-01-07 08:25:42" #time -3 hour for adjust gmt
date_time = datetime.datetime.strptime(time_input, "%Y-%m-%d %H:%M:%S")
timezone = pytz.timezone('Etc/GMT+0')  # GMT+0 zaman dilimi
date_time = timezone.localize(date_time)
time = int(date_time.timestamp())
nonce = "0x1256480b"
bits = '0x1703d869'
#result: 00000000000000000000a471409782866f26e21000cdced10ddbb048ff553878
calc3(markle_root, prev_block, version, time, bits, nonce)


prev_block = "63a47ff11619185396e318932fa8b79488e9fb0d00031abc0000000000000000"
prev_block = rev8(prev_block)
#prev_block = "000000000000000000031abc88e9fb0d2fa8b79496e318931619185363a47ff1"
markle_root = ("a957af6ec4cac7f9e209c457331dc0333aecd47672f97e243e14c380bed5337f")
#markle_root = "e62c1c96853f45e110a5b3911c22706a9aed8d0fac34e7441138bf7b46403d94"
markle_root = rev(markle_root)
#version = 0x2b58c000
#version = "279ce000"
version = "20000000"
#time_input = "2024-01-07 08:25:42" #time -3 hour for adjust gmt
#date_time = datetime.datetime.strptime(time_input, "%Y-%m-%d %H:%M:%S")
#timezone = pytz.timezone('Etc/GMT+0')  # GMT+0 zaman dilimi
#date_time = timezone.localize(date_time)
#time = int(date_time.timestamp())

bits = '0x1703d869'
time = "659a5d31"
time = int(time,16)
nonce = "0x1aa1787c"
print("=========================in==========================")
print("prev_block_in:", prev_block)
print("markle_root_in:", markle_root)
print("Version_in:    ", version)
print("bits_in:", bits)
print("Time_in:", time)
print("nonce_in:", nonce)
#TX SHARE: 22c34c2da30bc339a49a540624e0203e3d6db926431d2671955a688999010000
calc3(markle_root, prev_block, version, time, bits, nonce)