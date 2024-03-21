# Ghidra Assistant

This is the Ghidra extension required for Reverse Engineering Assistant to populate menus with ReVa entries and provide other features. 

## Prerequisites

You must have Gradle installed. 

## Build

The absolute path to the install folder of the Ghidra version you wish to use must be defined in `GHIDRA_INSTALL_DIR`. This can be done by setting an environment variable or by specifying `-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>` when you run gradle. 

In a terminal/cli navigate to the `ghidra-assistant` folder and run this:

```
gradle -PGHIDRA_INSTALL_DIR="E:\example\ghidra_11.0.1_PUBLIC"
```

Assuming the build succeeds, this will generate a zip file in the dist folder, the filename will look something like `reverse-engineering-assistant\ghidra-assistant\dist\ghidra_11.0.1_PUBLIC_20240321_ghidra-assistant.zip`

## Installation

Start Ghidra. In the Project Management window that opens first, select `File` -> `Install Extensions`. In the Install Extensions window, at the top right, there's a green plus sign. Click that. Locate your `ghidra-assistant.zip` file and click `OK`. Back in the Install Extensions window, ensure that the ReVa extension is enabled and click `OK`. 

To test, choose and open a file. Find a function and open its Decompile window. Right click on a variable name and you should see a "ReVa" option in the menu.

