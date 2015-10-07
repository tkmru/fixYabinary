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
__version__ = "0.2.4"
__date__ = "2015/09/11"
__minimum_python_version__ = (2, 7, 6)
__maximum_python_version__ = (3, 4, 3)
__copyright__ = "Copyright (c) @tkmru"
__license__ = "MIT License"


import re
import binascii
import sys
import argparse


headers = {"jpg": ["ff d8 ff"],
           "png": ["89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52"],
           "pdf": ["25 50 44 46"],
           "zip": ["50 4b 03 04",
                   "50 4b 05 06",
                   "50 4b 07 08",
                   "50 4b 4c 49 54 45",
                   "50 4b 53 70 58",
                   "57 69 6e 5a 69 70"],
           "7zip": ["37 7a bc af 27 1c"],
           "rar": ["52 61 72 21 1a 07 00"],
           "mp3": ["49 44 33"],
           "mp4": ["66 74 79 70 33 67 70 35",
                   "66 74 79 70 4D 53 4E 56",
                   "66 74 79 70 69 73 6F 6D"],
           "exe": ["4D 5A 90 00 03 00 00 00"]}

footers = {"jpg": ["ff d9"],
           "png": ["00 00 00 00 49 45 4e 44 ae 42 60 82"],
           "pdf": ["0a 25 25 45 4f 46",
                   "0a 25 25 45 4f 46 0a",
                   "0d 0a 25 25 45 4f 46 0d 0a",
                   "0d 25 25 45 4f 46 0d"]}


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


def save(target_path, binary):
    with open(target_path, "wb") as f:
        f.write(binascii.a2b_hex(binary))


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


def _extractElementAppearManyTimes(list):
    list_set = set(list)
    counter1 = 0
    element = ""

    for v in list_set:
        counter2 = list.count(v)

        if counter2 > counter1:
            element = v
            counter1 = counter2

    return element


def _findDataBeforeNextHeaderOrLast(data):
    indexies = []

    for key in headers.keys():
        for element in headers[key]:
            indexies += [(m.start(), key) for m in re.finditer(element, data)] # [(index, key),(index, key)...]

    indexies = sorted(indexies)
    results = []

    x = len(indexies) - 1
    if x == 0:
        result = data[indexies[0][0]:]
        results.append((result, indexies[0][1]))
    else:
        for i in range(x):
            if i == (x - 1):
                result = data[indexies[i][0]: indexies[i+1][0]]
                results.append((result, indexies[i][1]))
                result = data[indexies[i+1][0]:]
                results.append((result, indexies[i+1][1]))
            else:
                result = data[indexies[i][0]: indexies[i+1][0]]
                results.append((result, indexies[i][1]))

    return results


def extract(source_path, dest_path, start_address=None, end_address=None):
    """
    extract file in file. cut out file or auto detect file in file.
    """

    hex_data_formated = get(source_path, "f")

    result_list = []

    if (start_address is not None) and (end_address is not None):
        """
        cut out file
        """
        hex_list = hex_data_formated.split(" ")
        # if address is int, it interpret address is decimal
        if type(start_address) == str: # address to int
            start_address = int(start_address, 16)

        if type(end_address) == str: # address to int
            end_address = int(end_address, 16)

        result = "".join(hex_list[start_address: end_address + 1])
        result_list.append((result, None))

    elif (start_address is None) and (end_address is None):
        """
        auto detect file in file
        """
        data_lists = _findDataBeforeNextHeaderOrLast(hex_data_formated)

        if len(data_lists) != 0:
            for hex_data_formated_cut, key in data_lists:
                if key == "pdf" or key == "jpg" or key == "png":
                    for footer in footers[key]:
                        if footer in hex_data_formated_cut:
                            end_index = hex_data_formated_cut.find(footer)+len(footer)
                            result_list.append((hex_data_formated_cut[: end_index].replace(" ", ""), key))
                            break

                else: # footer don't match
                    hex_list = hex_data_formated.split(" ")
                    element = _extractElementAppearManyTimes(hex_list)

                    for _ in range(len(hex_list)):
                        if hex_list[-1] == element:
                            hex_list.pop()

                        else:
                            break

                    result_list.append(("".join(hex_list), key))

        else: # when Yabinary don't have header.
            hex_list = hex_data_formated.split(" ")
            element = _extractElementAppearManyTimes(hex_list)

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

            result_list.append(("".join(hex_list), None))

    else:
        raise Exception("Both third and fourth args must be None or address.")

    for index, result_tuple in enumerate(result_list):
        result, file_type = result_tuple[0], result_tuple[1]
        if index == 0:
            pass
        else:
            dest_path += str(index + 1)

        if file_type is None:
            with open(dest_path, "wb") as f:
                if sys.version_info[0] >= 3:
                    f.write(bytes.fromhex(result))
                else:
                    f.write(result.decode("hex"))
            print("Succeeded in making " + dest_path)

        else:
            dest_path = dest_path + "." + file_type

            with open(dest_path, "wb") as f:
                if sys.version_info[0] >= 3:
                    f.write(bytes.fromhex(result))
                else:
                    f.write(result.decode("hex"))

            print("Succeeded in making " + dest_path)


def identify(source_path):
    """
    identify file type in file
    """
    hex_data_formated = get(source_path, "f")
    indexies = []

    for key in headers.keys():
        for element in headers[key]:
            indexies += [key for m in re.finditer(element, hex_data_formated)]

    print(source_path + " include following file")
    for key in indexies: # tuple in indexies
        print(key)


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

    # identify("./test.jpg")
    # extract("./expanded", "./output")
    # extend("./test.jpg", "./expanded", "00", 10, "b")
    # look("./expanded")
    # print(get("./test.jpg"))
    # print(get("./test.jpg", "f"))
