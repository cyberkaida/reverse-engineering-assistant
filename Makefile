# Get the directory of the current Makefile
MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
REVA_PYTHON_PATH := $(MAKEFILE_PATH)/reverse-engineering-assistant/reverse_engineering_assistant

.PHONY: protocol ghidra python all clean

all: protocol ghidra python
clean:
ifeq ($(OS),Windows_NT)
	rmdir /S /Q "$(REVA_PYTHON_PATH)/protocol" 2> NUL || (exit 0)
	rmdir /S /Q reverse-engineering-assistant\dist 2> NUL || (exit 0)
	rmdir /S /Q reverse-engineering-assistant\build 2> NUL || (exit 0)
	rmdir /S /Q ghidra-assistant\build 2> NUL || (exit 0)
	rmdir /S /Q ghidra-assistant\dist 2> NUL || (exit 0)
else
	rm -rf $(REVA_PYTHON_PATH)/protocol
	rm -rf reverse-engineering-assistant/dist reverse-engineering-assistant/build
	rm -rf ghidra-assistant/build ghidra-assistant/dist
endif
	gradle -b $(MAKEFILE_PATH)/ghidra-assistant/build.gradle clean

ghidra: protocol
	gradle -b $(MAKEFILE_PATH)/ghidra-assistant/build.gradle

python: protocol
	python3 -m pip install build
	python3 -m build reverse-engineering-assistant

# Generate Python code from proto file
protocol: create_protocol
	python3 -m pip install -r $(MAKEFILE_PATH)/requirements.txt
	python3 -m grpc_tools.protoc \
		--proto_path=$(MAKEFILE_PATH)/protocol/ \
		--python_out=$(REVA_PYTHON_PATH)/protocol/ \
		--pyi_out=$(REVA_PYTHON_PATH)/protocol/ \
		--grpc_python_out=$(REVA_PYTHON_PATH)/protocol/ \
		$(MAKEFILE_PATH)/protocol/*.proto

create_protocol:
ifeq ($(OS),Windows_NT)
	if not exist "$(REVA_PYTHON_PATH)/protocol" mkdir "$(REVA_PYTHON_PATH)/protocol"
	echo.> $(REVA_PYTHON_PATH)/protocol/__init__.py
else
	mkdir -p "$(REVA_PYTHON_PATH)/protocol"
	touch $(REVA_PYTHON_PATH)/protocol/__init__.py
endif
