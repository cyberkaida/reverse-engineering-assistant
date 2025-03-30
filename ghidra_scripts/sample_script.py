# Sample PyGhidra GhidraScript
# @category Examples
# @runtime PyGhidra

from java.util import LinkedList
java_list = LinkedList([1,2,3])

block = currentProgram.memory.getBlock('.text')
