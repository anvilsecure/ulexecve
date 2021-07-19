# ulexecve

these are some samples to do userland execve() things

the memfd_create() is the simplest trick that works on most post 3.x kernels, however
it's not very stealthly but it works in a lot of cases and super solidly

way more stealthily however is parsing the ELF properlyi and mapping in every needed
segment, setting up a jump buffer and then jumping into the new ELF; as this would
only require mmap() + mprotect() and there's no execve*() family function called which
are easily auditable

the approach taken was basically what rapid7's mettle does; see the mapping
code at https://github.com/rapid7/mettle/blob/fbe4f1370ad4f6258629c123fd661c88881ac68e/libreflect/src/map_elf.c

problem is that in the current poc it works for python2 but that's more by chance than
anything else; what needs to be done is to update the script to simply collect all
the data via the python parser, then make a way more complicated jump buf that uses
raw instructiosn to copy the data in place over the mapped code of the python interpreter



-- gvb@



