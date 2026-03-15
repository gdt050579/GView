GView Core
==========

Core
----

This section covers internal and format-specific details used by GViewCore and
various Type plugins. Content is expanded over time.

Golang binary support (references)
------------------------------------

Type plugins (e.g. PE, ELF, Mach-O) use the following references for Go symbol and
runtime parsing:

* `Go runtime symtab <https://go.dev/src/runtime/symtab.go>`__
* `Go runtime2 <https://go.dev/src/runtime/runtime2.go>`__
* `gosym/pclntab <https://go.dev/src/debug/gosym/pclntab.go>`__
* `go_parser pclntbl <https://github.com/0xjiayu/go_parser/blob/master/pclntbl.py>`__
* `golang_loader_assist <https://github.com/strazzere/golang_loader_assist>`__
* `Mandiant: Golang internals - symbol recovery <https://www.mandiant.com/resources/golang-internals-symbol-recovery>`__
* `Go binaries in Cutter <https://github.com/dutchcoders/jupyter-radare2>`__