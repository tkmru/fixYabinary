===========
fixYabinary
===========

| This is Python Library to fix "Yabinary" file like foremost. 
 The term "Yabinary" in Japanese mean "Dangerous Binary". 
| This library can be useful for CTF. It supports Python 2 & 3. 
| docment in Japanese(http://tkmr.hatenablog.com/entry/2014/03/25/222207) 

change log
==========
| 0.3.0
| extract() return dict
| change -x to -c, -a to -x
| 0.2.9
| update signatures
| add check_hidden_data()
| 0.2.8
| add many signatures
| change extract single files to extract many files
| 0.2.7
| bug fix
| 0.2.6
| add get_signature_index(), rewite identify(), extract()
| 0.2.5
| add write()
| 0.2.4
| fix README
| 0.2.3
| change fixYabinary command, import to fy
| 0.2.2
| bug fix
| 0.2.1
| rewrite something, and change how to extend().
| 0.2.0
| can use in command line.

Installation
============

----
PyPI
----
The recommended process is to install the PyPI package, as it allows easily staying update.

::

    $ pip install fixYabinary

------
github
------
Download from https://github.com/tkmru/fixYabinary/.
Let's push star!!


Usage
=====

---------------
look(file_path)
---------------

print Binary like hexdump command.

::

    >> import fy
    >> fy.look("./test.png")

               00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F
    0x000000   00 00 00 00 49 45 4e 44   ae 42....


It can be used in command line.

::

    $ fy -l test.png


----------------------
get(file_path, option)
----------------------

| return Binary data. If option is "f" , you get Formated Binary.
| You must not set option.

::

    >> import fy
    >> fy.get("./test.png")
    0000000049454e44ae42....

    >>fy.get("./test.png", "f")
    00 00 00 00 49 45 4e 44 ae 42....


---------------------------------
write(file_path, binary, option)
---------------------------------

| This function write new file from binary string.
| If option is "l" , set binary list to second arg.
| You must not set option.

::

    >> import fy
    >> fy.write('test','01ff4c')
    >> fy.get('test')
    u'01ff4c'

    >> fy.write('test',['01','ff','4c'],'l')
    >> fy.get('test')
    u'01ff4c'


------------------------------------------------------------------------------
extend(file_path, new_file_path, hex, bytes, option)
------------------------------------------------------------------------------

| make new file that file is extended.
  extend function intepret that byte is decimal.  
| option is None or "t" or "b". option is None by default. 

::

    >> import fy
    >> fy.get("./test.png", "./extended", "00", 3)

    Succeeded in making ./extended.
    # 000000 + ./test.png's Binary Data + 000000 in ./extended


    >> fy.get("./test.png", "./extended", "00", 3, "t")

    Succeeded in making ./extended.
    # 000000 + ./test.png's Binary Data in ./extended 


    >> fy.get("./test.png", "./extended", "00", 3, "b")

    Succeeded in making ./extended.
    # ./test.png's Binary Data + 000000 in ./extended  


It can be used in command line in case option is None.

::

    $ fy -e test.png extended 00 3


-------------------
identify(file_path)
-------------------

identify file type in file. return file type.

::

    >> import fy
    >> fy.identify("./extended")
    ./expanded include following FILE SIGNATURES
    This file include hidden file.
    File type: gif Detect: 4 files
    HEADER
    0 bytes - 5 bytes, 2791486 bytes - 2791491 bytes, 5578481 bytes - 5578486 bytes, 8366075 bytes - 8366080 bytes
    FOOTER
    6941 bytes - 6942 bytes, 2793128 bytes - 2793129 bytes, 2794238 bytes - 2794239 bytes, 5580894 bytes - 5580895 bytes, 8368828 bytes - 8368829 bytes

    File type: png Detect: 4 files
    HEADER
    6943 bytes - 6958 bytes, 2794240 bytes - 2794255 bytes, 5580896 bytes - 5580911 bytes, 8368830 bytes - 8368845 bytes
    FOOTER
    9715 bytes - 9726 bytes, 2796205 bytes - 2796216 bytes, 5583366 bytes - 5583377 bytes, 8371920 bytes - 8371931 bytes


It can be used in command line.

::

    $ fy -i extended


-------------------------------------------------------------
extract(file_path, new_file_path, start_address, end_address)
-------------------------------------------------------------

| cut out binary data, and write it into new file.
| If start_address and end_address is str, they are interpreted hex.
| If start_address and end_address is int, they are interpreted decimal.

::

    >> import fy
    >> fy.extract("./extended", "./result", 4 , 124)
    OrderedDict([(None, ['./cutout'])])

and auto detect file in file, and write it into new file.

::

    >> import fy
    >> fy.extract("./extended", "./result")
    OrderedDict([('png', ['result1.png', 'result2.png', 'result3.png', 'result4.png']), ('gif', ['result5.gif', 'result6.gif', 'result7.gif', 'result8.gif']), ('jpg', ['result9.jpg', 'result10.jpg', 'result11.jpg', 'result12.jpg'])])

It can be used in command line.

::

    $ fy -c extended result 4 124  # set start_address and end_address

    $ fy -x extended result        # auto extract file in file

    $ fy -x extended               # if new_file_path is None, auto set ./result to new_file_path


License
=======

MIT License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Copyright (c) @tkmru 