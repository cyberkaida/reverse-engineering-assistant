"""
Test PyGhidra integration for headless Ghidra operation.

Verifies that:
- PyGhidra can be imported
- Ghidra can be initialized in headless mode
- Basic Ghidra functionality works (program creation, etc.)
"""

import pytest


class TestPyGhidraIntegration:
    """Test that PyGhidra integration works correctly"""

    def test_pyghidra_imports(self):
        """PyGhidra module can be imported"""
        import pyghidra
        assert pyghidra is not None

    def test_ghidra_initialized(self, ghidra_initialized):
        """Ghidra can be initialized in headless mode"""
        # The fixture handles initialization
        # Just verify we can import Ghidra classes
        from ghidra.program.database import ProgramDB
        from ghidra.program.model.lang import LanguageID
        assert ProgramDB is not None
        assert LanguageID is not None

    def test_test_program_created(self, test_program):
        """Test program fixture creates valid program"""
        assert test_program is not None, "Failed to create test program"

        # Verify program properties
        assert test_program.getName() == "TestHeadlessProgram"

        # Verify memory was created
        memory = test_program.getMemory()
        assert memory is not None

        # Verify .text section exists
        text_block = memory.getBlock(".text")
        assert text_block is not None
        assert text_block.getStart().getOffset() == 0x00401000
        assert text_block.getSize() == 0x1000

    def test_reva_classes_importable(self, ghidra_initialized):
        """ReVa classes can be imported after Ghidra initialization"""
        from reva.headless import RevaHeadlessLauncher
        assert RevaHeadlessLauncher is not None
