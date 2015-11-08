#!/usr/bin/env python
# coding: UTF-8

"""
Tool to Fix Yabinary File
It is useful to use on CTF.

Use at your own risk.

Released under MIT License.
"""

__description__ = "Tool to Fix Yabinary File"
__author__ = "@tkmru"
__version__ = "0.2.6"
__date__ = "2015/11/9"
__minimum_python_version__ = (2, 7, 6)
__maximum_python_version__ = (3, 5, 0)
__copyright__ = "Copyright (c) @tkmru"
__license__ = "MIT License"


import re
import binascii
import sys
import argparse


headers = {"jpg": ["ffd8ff"],
           "png": ["89504e470d0a1a0a0000000d49484452"],
           "pdf": ["25504446"],
           "zip": ["504b0304",
                   "504b0506",
                   "504b0708",
                   "504b4c495445",
                   "504b537058",
                   "57696e5a6970"],
           "7zip": ["377abcaf271c"],
           "rar": ["526172211a0700"],
           "mp3": ["494433"],
           "mp4": ["6674797033677035",
                   "667479704D534E56",
                   "6674797069736F6D"],
           "exe": ["4D5A900003000000"]}

footers = {"jpg": ["ffd9"],
           "png": ["0000000049454e44ae426082"],
           "pdf": ["0a2525454f46",
                   "0a2525454f460a",
                   "0d0a2525454f460d0a",
                   "0d2525454f460d"]}


def get(source_path, option=None):
    """
    get Binary data. If option is \"f\" , you get Formated Binary.
    """
    try:
        with open(source_path, "rb") as f:
            hex_data = binascii.hexlify(f.read()).decode('utf-8')

            if option is None:
                return hex_data

            elif option == "f":
                return re.sub("(..)", r"\1 ", hex_data)[:-1]

            else:
                raise Exception("option must be 'f' or None")

    except IOError:
        raise IOError("Source path is wrong.")


def write(target_path, binary, option=None):
    with open(target_path, "wb") as f:
        if option is None:
            f.write(binascii.a2b_hex(binary))

        elif option == 'l':
            binary_list = map(lambda n: int(n, 16), binary)
            binary_byte_array = bytearray(binary_list)
            f.write(binary_byte_array)

        else:
            raise Exception("option must be 'l' or None")


def look(source_path):
    """
    look Binary like hexdump
    """
    hex_data_formated = get(source_path, "f")
    hex_list = hex_data_formated.split(" ")

    result = "           00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F\n"
    for index, value in enumerate(hex_list):
        if index == 0:
            result += ("0x000000   " + value + " ")

        elif index % 16 == 15:
            address = hex(index + 1)
            result += (value + "\n" + address[0:2] + address[2:].zfill(6) + "   ")

        elif index % 16 == 7:
            result += (value + "   ")

        else:
            result += (value + " ")

    print(result)


def _extract_element_appeared_many_times(list):
    list_set = set(list)
    counter1 = 0
    element = ""

    for v in list_set:
        counter2 = list.count(v)

        if counter2 > counter1:
            element = v
            counter1 = counter2

    return element


def extract(source_path, dest_path, start_address=None, end_address=None):
    '''
    extract file in file. cut out file or auto detect file in file.
    '''

    result_data = () # (result (hex data, file type)

    if (start_address is not None) and (end_address is not None):
        """
        cut out file
        """
        hex_data_formated = get(source_path, "f")
        hex_list = hex_data_formated.split(" ")
        # if address is int, it interpret address is decimal
        if type(start_address) == str: # address to int
            start_address = int(start_address, 16)

        if type(end_address) == str: # address to int
            end_address = int(end_address, 16)

        result = "".join(hex_list[start_address: end_address + 1])
        result_data = (result, None)

    elif (start_address is None) and (end_address is None):
        '''
        auto detect file in file
        '''
        hex_data = get(source_path)
        header_indexies = get_signature_index(hex_data, headers)

        if len(header_indexies) != 0:
            '''
            use header smallest address
            '''
            result_filetype = header_indexies.keys()[0]
            min_begin_index = header_indexies[result_filetype][0][0]
            for filetype, header_indexies_list in header_indexies.items():
                for header_index in header_indexies_list:
                    if header_index[0] < min_begin_index:
                        min_begin_index = header_index[0]
                        result_filetype = filetype

            footer_indexies = get_signature_index(hex_data, footers)
            max_end_index = 0
            if result_filetype in footer_indexies:
                '''
                use footer largest address
                '''
                for footer in footer_indexies[result_filetype]:
                    if max_end_index < footer[1]:
                        max_end_index = footer[1]

                result_data = (hex_data[min_begin_index: max_end_index+1], result_filetype)

            else: # footer don't match remove data appeared many times
                hex_data_formated = get(source_path, "f")
                hex_list = hex_data_formated.split(" ")
                element = _extract_element_appeared_many_times(hex_list)

                for _ in range(len(hex_list)):
                    if hex_list[-1] == element:
                        hex_list.pop()

                    else:
                        break

                result_data = ("".join(hex_list), result_filetype)

        else: # when Yabinary don't have header and footer.
            '''
            remove data appeared many times
            '''
            hex_data_formated = get(source_path, "f")
            hex_list = hex_data_formated.split(" ")
            element = _extract_element_appeared_many_times(hex_list)

            for _ in range(len(hex_list)):
                if hex_list[-1] == element:
                    hex_list.pop()
                    if hex_list[0] == element:
                        hex_list.reverse()
                        hex_list.pop()
                        hex_list.reverse()

                else:
                    if hex_list[0] == element:
                        hex_list.reverse()
                        hex_list.pop()
                        hex_list.reverse()
                    else:
                        break

            result_data = ("".join(hex_list), None) # file type is None

    else:
        raise Exception("Both third and fourth args must be None or address.")

    result_binary_string, file_type = result_data[0], result_data[1]

    if file_type is None:
        with open(dest_path, "wb") as f:
            if sys.version_info[0] >= 3:
                f.write(bytes.fromhex(result_binary_string))
            else:
                f.write(result_binary_string.decode("hex"))
        print("Succeeded in making " + dest_path)

    else:
        dest_path = dest_path + "." + file_type

        with open(dest_path, "wb") as f:
            if sys.version_info[0] >= 3:
                f.write(bytes.fromhex(result_binary_string))
            else:
                f.write(result_binary_string.decode("hex"))

        print("Succeeded in making " + dest_path)


def identify(source_path):
    """
    identify file type in file
    """
    hex_data = get(source_path)

    print(source_path + " include following FILE SIGNATURES")

    print('HEADER')
    for file_type, indexies in get_signature_index(hex_data, headers).items():
        result = file_type+': '
        for i, location in enumerate(indexies):
            if i == (len(indexies)-1):
                result += str(location[0]/2) + ' bytes - ' + str((location[1]-1)/2) + ' bytes'
            else:
                result += str(location[0]/2) + ' bytes - ' + str((location[1]-1)/2) + ' bytes, '
        print result

    print('\nFOOTER')
    for file_type, indexies in get_signature_index(hex_data, footers).items():
        result = file_type+': '
        for i, location in enumerate(indexies):
            if i == (len(indexies)-1):
                result += str(location[0]/2) + ' bytes - ' + str((location[1]-1)/2) + ' bytes'
            else:
                result += str(location[0]/2) + ' bytes - ' + str((location[1]-1)/2) + ' bytes, '
        print result


def extend(source_path, dest_path, hex, bytes, option=None):
    """
    make new file extended old file
    """

    hex_data = get(source_path)

    if option is None:
        new_hex_data = str(hex) * int(bytes) + hex_data + str(hex) * int(bytes)

    elif option == 't':
        new_hex_data = str(hex) * int(bytes) + hex_data

    elif option == 'b':
        new_hex_data = hex_data + str(hex) * int(bytes)

    try:
        with open(dest_path, "wb") as f:
            if sys.version_info[0] >= 3:
                f.write(bytes.fromhex(new_hex_data))
            else:
                f.write(new_hex_data.decode("hex"))

        print("Succeeded in making " + dest_path)

    except IOError:
        raise IOError("Dest path is wrong.")


def get_signature_index(binary_string, signatures_dict):
    result = {}
    for key, signatures_list in signatures_dict.items():
        indexies = []
        for signature in signatures_list:
            # if m.start() % 2 check correct match
            indexies += [[m.start(), m.start()+len(signature)-1] for m in re.finditer(signature, binary_string) if m.start() % 2 == 0]

        if indexies != []:
            result[key] = indexies

    return result # return value: {file type:[[begin index, end index], [begin index, end index]]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__description__)
    parser.add_argument('-l', '--look', nargs=1, metavar='source_path', help='look binary like hexdump command.')
    parser.add_argument('-i', '--identify', nargs=1, metavar='source_path', help='identify file type in file.')
    parser.add_argument('-e', '--extend', nargs=4, metavar=('source_path', 'dest_path', 'hex', bytes), help='make new file that file is extended.')
    parser.add_argument('-r', '--extract', nargs=4, metavar=('source_path', 'dest_path', 'start_address', 'end_address'), help='extract file in file.')
    parser.add_argument('-a', '--auto_extract', nargs=2, metavar=('source_path', 'dest_path'), help='auto extract file in file.')
    parser.add_argument('--version', '-v', action='version', version=__version__)

    args = parser.parse_args()

    if args.look:
        look(args.look[0])
    elif args.identify:
        identify(args.identify[0])
    elif args.extend:
        extend(args.extend[0], args.extend[1], args.extend[2], args.extend[3], args.extend[4], args.extend[5])
    elif args.extract:
        extract(args.extract[0], args.extract[1], args.extract[2], args.extract[3])
    elif args.auto_extract:
        extract(args.auto_extract[0], args.auto_extract[1])

    # for debug
    # identify('./a.pdf')
    # extract("./expanded", "./output")
    # extract("./expanded", "./output", 10, 30)
    # extend('./a.pdf', "./expanded", "00", 10)
    # look("./expanded")
    # print(get("./test.jpg"))
    # print(get("./test.jpg", "f"))
    # print get_signature_index(get('./a.pdf'), headers)
