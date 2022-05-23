OpENer File Object
=========================

Welcome to OpENer File Object!

OpENer File Object is an extension object to [OpENer](https://github.com/EIPStackGroup/OpENer), providing an OpENer-compatible implementation of the File Object&trade;.
As [OpENer](https://github.com/EIPStackGroup/OpENer) it is licensed under the adapted BSD-style license (see [License](https://github.com/EIPStackGroup/OpENerElectricalEnergyObject/blob/master/license.txt)).

So you may ask "Why is this not directly part of [OpENer](https://github.com/EIPStackGroup/OpENer)?", and this is a valid question.
The answer to this is, that [OpENer](https://github.com/EIPStackGroup/OpENer) is focused on providing a near-to-minimal, but state of the art, implementation of a EtherNet/IP&trade; adapter device.
Nonetheless, we now and then develop additional objects for our usage, but cannot be strictly considered to be part of the [OpENer](https://github.com/EIPStackGroup/OpENer) project.
Hence, such objects are provided as separate project. Another benefit of this approach is, that [OpENer](https://github.com/EIPStackGroup/OpENer) does not get cluttered with a giantic library (ok, not really giantic, but you get the point) of objects.

So, how do you use this? Again a good question! For some time already [OpENer](https://github.com/EIPStackGroup/OpENer) got a "drop-in" CMake-configure mechanism for additional object, when put into the *cip_objects* directory (you probably already asked yourself, whats this empty directory for?)

So the easiest way is to `git clone` this repository into the *cip_objects* directory and hit the `Configure` button in CMake, which should give you a checkbox for this object (OpENer_CIP_OBJECT_CIP_FILE_OBJECT).
Hit `Configure` again and then `Generate`. Now the object is included into the [OpENer](https://github.com/EIPStackGroup/OpENer) compile process.


Contributing to OpENer File Object:
-----------------------
The easiest way is to fork the repository, then create a feature/bugfix branch.
After finishing your feature/bugfix create a pull request and explain your changes.
Also, please update and/or add doxygen comments to the provided code sections.
Please stick to the coding conventions, as defined in source/doc/coding_rules
The easiest way to conform to the indenting convertion is to set uncrustify as git filter in the OpENer repository, which can be done with the following to commands:

```
git config filter.uncrustify.clean "/path/to/uncrustify/uncrustify -c uncrustify.cfg --mtime --no-backup"

git config filter.uncrustify.smudge "cat"
```
