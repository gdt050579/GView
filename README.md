# GView

![Build icon](https://github.com/gdt050579/AppCUI/actions/workflows/ci.yml/badge.svg)

- [GView](#gview)
	- [General description](#general-description)
	- [Architecture](#architecture)
	- [Building](#building)
		- [Tools used](#tools-used)
		- [Supported platforms](#supported-platforms)
			- [Windows](#windows)
			- [OSX](#osx)
			- [Linux](#linux)
	- [CI/CD](#cicd)
	- [Documentation](#documentation)
	- [Start contributing](#start-contributing)

## General description 
**GView** can be described as a hex viewer for files or any type of data (buffer, memory zone) which has a structure that you can create a plugin to parse it and use any of the available views (or a custom view that can be also created) to represent it.

## Architecture
![alt text for screen readers](/docs/source/_static/GView.svg "High level architecture at the current moment.").

![alt text for screen readers](/docs/source/_static/GViewCore.svg "Core architecture at the current moment.").

## Building
### Tools used
CMake is used to build the entire project regardless of the platform.
### Supported platforms
#### Windows
Requires a manual installation of `OpenSSL 1.x`. You can get an already built .msi or .exe or you can install it via package manager [vcpkg](https://github.com/microsoft/vcpkg).
You can grab an `OpenSSL 1.x` binary from [here](https://slproweb.com/products/Win32OpenSSL.html).
Usage of [vcpkg](https://github.com/microsoft/vcpkg) in our build pipeline can be seen [here](/.github/workflows/ci.yml).
#### OSX
Works out of the box as long as you have an installation of `OpenSSL 1.x`.
#### Linux
Works out of the box as long as you have an installation of `OpenSSL 1.x`.

## CI/CD
At the moment we are using `Github Actions` ensuring that the project builds on `Windows`, `OSX` & `Linux` and we are working towards creating artefacts, storing them and eventually building a release flow.
For static analysis, we are using `CodeQL` & `Microsoft C++ Code Analysis`.

## Documentation 
The project uses Sphinx as the main documentation engine. Sphinx sources can be located under `docs` folder.

On every commit to `main`, a compiled version of the Sphinx documentation is published to `gh-pages` and then to [docs](https://gdt050579.github.io/GView).

## Start contributing
- Clone this repository using recurse submodules: 
```bash
	git clone --recurse-submodules <your-repo-link/GView.git>
```

Contributors can install sphinx using `pip install -r requirements.txt`, this will install Sphinx tooling and `sphinx_rtd_theme`. Local building is done with `make html`

After the command executes successfully, the html pages can be found in the `build` folder.
