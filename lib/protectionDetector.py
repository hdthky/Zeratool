from pwn import *

def getProperties(binary_name):
    
    properties = {}
    binary = ELF(binary_name)
    properties['pie'] = binary.pie
    properties['aslr'] = binary.aslr
    properties['arch'] = binary.arch
    properties['canary'] = binary.canary
    properties['nx'] = binary.nx
    properties['relro'] = binary.relro
    properties['got'] = binary.got
    properties['plt'] = binary.plt
    if binary.pie:
        for got_item in properties['got']:
            properties['got'][got_item] += 0x56555000
        for plt_item in properties['plt']:
            properties['plt'][plt_item] += 0x56555000

    return properties

