#!/usr/bin/env python
# coding: UTF-8

"""
Tool to Fix Yabinary File
It is useful to use on CTF.

Use at your own risk.

Released under MIT License.
"""

__description__ = 'Tool to Fix Yabinary File'
__author__ = '@tkmru'
__version__ = '0.1.0'
__date__ = '2014/03/23'
__copyright__ = "Copyright (c) @tkmru"
__license__ = "MIT License"


import re

headers = { "jpg": ["ff d8 ff"],
            "png" : ["89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52"],
            "pdf" : ["25 50 44 46"],            
            "zip" : ["50 4b 03 04",
                     "50 4b 05 06",
                     "50 4b 07 08",
                     "50 4b 4c 49 54 45",
                     "50 4b 53 70 58",
                     "57 69 6e 5a 69 70"],
            "7zip": ["37 7a bc af 27 1c"],
            "rar" : ["52 61 72 21 1a 07 00"],
            "mp3" : ["49 44 33"],
            "mp4" : ["66 74 79 70 33 67 70 35"
                     "66 74 79 70 4D 53 4E 56"
                     "66 74 79 70 69 73 6F 6D"],
            "exe" : ["4D 5A 90 00 03 00 00 00"]
          }

footers = { "jpg": ["ff d9"],
            "png" : ["00 00 00 00 49 45 4e 44 ae 42 60 82"],
            "pdf" : ["0a 25 25 45 4f 46",
                     "0a 25 25 45 4f 46 0a",
                     "0d 0a 25 25 45 4f 46 0d 0a",
                     "0d 25 25 45 4f 46 0d"]
          }


def get(file_path, option=None):
    """
    get Binary data. If option is \"f\" , you get Formated Binary. 
    """
    try:
        with open(file_path, "rb") as f:
            hex_data = f.read().encode("hex")

            if option is None:
                return hex_data

            elif option == "f":
                return re.sub('(..)', r'\1 ', hex_data)[:-1]

    except IOError:
        raise Exception("First arg is wrong path.")

    except:
        raise Exception( "option must be \"f\" or None")


def look(file_path):
    """
    look Binary like Binary editer
    """
    hex_data_formated = get(file_path, "f")
    hex_list = hex_data_formated.split(' ')

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

    print result


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
            indexies += [(m.start(), key) for m in re.finditer(element, data)] #[(index, key),(index, key)...]

    indexies = sorted(indexies)
    results = []

    x = len(indexies) - 1
    if x == 0:
        result = data[indexies[0][0]:]
        results.append((result, indexies[0][1]))
    else:
        for i in range(x):
            if i == (x - 1):
                result = data[indexies[i][0] : indexies[i+1][0] ]
                results.append((result, indexies[i][1]))
                result = data[indexies[i+1][0] : ]
                results.append((result, indexies[i+1][1]))
            else:
                result = data[indexies[i][0] : indexies[i+1][0] ]
                results.append((result, indexies[i][1]))

    return results


def extract(file_path, new_file_path, start_address=None, end_address=None):
    """
    extract file in file. cut out file or auto detect file in file. 
    """
    try:
        hex_data_formated = get(file_path, "f")

    except IOError:
        raise Exception( "First arg is wrong path." )

    result_list = []

    if (start_address is not None) and (end_address is not None):
        """
        cut out file
        """
        hex_list = hex_data_formated.split(' ')
        if type(start_address) == str: # hex to int
            start_address = int(start_address, 16)

        if type(end_address) == str: # hex to int
            end_address = int(end_address, 16)

        result = "".join(hex_list[start_address : end_address + 1])
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
                            result_list.append((hex_data_formated_cut[ : end_index].replace(" ",""), key))
                            break

                else: # footer don't match
                    hex_list = hex_data_formated.split(' ')
                    element = _extractElementAppearManyTimes(hex_list)

                    for _ in range(len(hex_list)):
                        if hex_list[-1] == element:
                            hex_list.pop()

                        else:
                            break

                    result_list.append(("".join(hex_list), key))

        else: # when Yabinary don't have header. 
            hex_list = hex_data_formated.split(' ')
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
        raise Exception("Both second and third args must be None or address.")

    try:
        for index, result_tuple in enumerate(result_list):
            result, file_type = result_tuple[0], result_tuple[1]
            if index == 0:
                pass
            else:
                new_file_path += str(index + 1)

            if file_type is None:
                with open(new_file_path, 'wb') as f:
                    f.write(result.decode("hex"))
                print "Succeeded in making " + new_file_path

            else:
                new_file_path = new_file_path + "." + file_type
                with open(new_file_path, 'wb') as f:
                    f.write(result.decode("hex"))
                print "Succeeded in making " + new_file_path

    except IOError:
        raise Exception( "Second arg is wrong path.")


def identify(file_path):
    """
    identify file type in file
    """
    hex_data_formated = get(file_path, "f")
    indexies = []

    for key in headers.keys():
        for element in headers[key]:
            indexies += [(m.start(), key) for m in re.finditer(element, hex_data_formated)]

    indexies = sorted(indexies)
    result = ""

    for index, key in indexies:
        result += key + "\n"

    print result


def extend(file_path, new_file_path, top_hex, top_bytes, bottom_hex="00", bottom_bytes=0):
    """
    make new file that is extended file
    """
    try:
        hex_data = get(file_path)

    except IOError:
        raise Exception( "First arg is wrong path." )


    if len(top_hex) == 1:
        top_hex = "0" + top_hex

    if len(bottom_hex) == 1:
        top_hex = "0" + top_hex


    try:
        new_hex_data = str(top_hex) * top_bytes + hex_data + str(bottom_hex) * bottom_bytes

    except TypeError:
        if type(top_bytes) == str: # hex to int
            start_address = int(start_address, 16)

        if type(bottom_bytes) == str: # hex to int
            end_address = int(end_address, 16)        

    try:
        with open(new_file_path, "wb") as f:
            f.write(new_hex_data.decode("hex"))
            print "Succeeded in making " + new_file_path

    except IOError:
        raise Exception( "Second arg is wrong path." )
"""
if __name__ == "__main__":
    #print identify("./test.png")
    #print extract("./expanded", "./output")
    #print extend("./test.ppg", "./expanded", "00", 10, "00", 10)
    #print look("./test.png")
    #print get("./test.png")
"""