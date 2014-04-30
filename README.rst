===========
fixYabinary
===========

This is Python Library to Fix Yabinary File like foremost.

The term "Yabinary" in Japanese mean "Dangerous Binary".

This library can be useful for CTF.


Installation
============

----
PyPI
----
The recommended process is to install the PyPI package, as it allows easily staying update.

::

    $ pip install fixYabinary

-------
Archive
-------
Download from https://github.com/tkmru/fixYabinary/.



Usage
=====

---------------
look(file_path)
---------------

print Binary like hexdump command.

::

    >> import fixYabinary
    >> fixYabinary.look("./test,png")

               00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F
    0x000000   00 00 00 00 49 45 4e 44 ae 42....


----------------------
get(file_path, option)
----------------------

return Binary data. If option is "f" , you get Formated Binary.
You must not set option.

::

    >> import fixYabinary
    >> fixYabinary.get("./test.png")
    0000000049454e44ae42....

    >>fixYabinary.get("./test.png", "f")
    00 00 00 00 49 45 4e 44 ae 42....

------------------------------------------------------------------------------
extend(file_path, new_file_path, top_hex, top_bytes, bottom_hex, bottom_bytes)
------------------------------------------------------------------------------

make new file that file is extended.
If top_byte and bottom_byte is str, they are hex.
If top_byte and bottom_byte is int, they are decimal.

::

    >> import fixYabinary
    >> fixYabinary.get("./test.png", "./extended", "00", 3, "00", 3)

    Succeeded in making ./extended
    # 000000 + ./test.png's Binary Data + 000000 in ./extended  

-------------------
identify(file_path)
-------------------

identify file type in file. return file type.

::

    >> import fixYabinary
    >> fixYabinary.get("./extended")
    png

-------------------------------------------------------------
extract(file_path, new_file_path, start_address, end_address)
-------------------------------------------------------------

cut out binary data, and write it into new file.
If start_address and end_address is str, they are hex.
If start_address and end_address is int, they are decimal.

::

    >> import fixYabinary
    >> fixYabinary.extract("./extended", "./result", 4 , 124)
    Succeeded in making ./result

and auto detect file in file, and write it into new file.

::

    >> import fixYabinary
    >> fixYabinary.extract("./extended", "./result")
    Succeeded in making ./result.png




License
=======

MIT License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Copyright (c) @tkmru 