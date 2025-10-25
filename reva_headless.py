#!/usr/bin/env python3
"""
ReVa Headless Launcher

This script launches the ReVa MCP server in headless mode using pyghidra.
It provides a command-line interface for starting the server without Ghidra's GUI.

Usage:
    # Start server with default settings (localhost:8080)
    python reva_headless.py

    # Start server with custom host and port
    python reva_headless.py --host 0.0.0.0 --port 9000

    # Start server and load a Ghidra project with programs
    python reva_headless.py --project-dir /path/to/projects --project-name MyProject --programs /binary1.exe /binary2.exe

Requirements:
    - pyghidra (pip install pyghidra)
    - GHIDRA_INSTALL_DIR environment variable set
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('reva-headless')

# Global launcher instance for signal handling
launcher_instance = None


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down...")
    if launcher_instance:
        launcher_instance.shutdown()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Launch ReVa MCP server in headless mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server with defaults
  %(prog)s

  # Start server on all interfaces
  %(prog)s --host 0.0.0.0 --port 9000

  # Load a Ghidra project
  %(prog)s --project-dir ~/ghidra_projects --project-name MyProject

  # Load specific programs from a project
  %(prog)s --project-dir ~/ghidra_projects --project-name MyProject --programs /binary1 /binary2

Environment Variables:
  GHIDRA_INSTALL_DIR    Path to Ghidra installation (required)
  REVA_EXTENSION_DIR    Path to ReVa extension directory (optional, defaults to current directory)
        """
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind the MCP server to (default: 127.0.0.1)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port for the MCP server (default: 8080)'
    )

    parser.add_argument(
        '--project-dir',
        type=str,
        help='Path to the Ghidra project directory'
    )

    parser.add_argument(
        '--project-name',
        type=str,
        help='Name of the Ghidra project to open'
    )

    parser.add_argument(
        '--programs',
        nargs='+',
        help='List of program paths within the project to load (e.g., /binary.exe)'
    )

    parser.add_argument(
        '--extension-dir',
        type=str,
        help='Path to ReVa extension directory (defaults to current directory)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Check for required environment variables
    ghidra_install = os.getenv('GHIDRA_INSTALL_DIR')
    if not ghidra_install:
        logger.error("GHIDRA_INSTALL_DIR environment variable not set")
        logger.error("Please set it to your Ghidra installation directory")
        sys.exit(1)

    if not os.path.isdir(ghidra_install):
        logger.error(f"GHIDRA_INSTALL_DIR points to non-existent directory: {ghidra_install}")
        sys.exit(1)

    logger.info(f"Using Ghidra installation: {ghidra_install}")

    # Determine ReVa extension directory
    extension_dir = args.extension_dir or os.getenv('REVA_EXTENSION_DIR') or os.getcwd()
    extension_dir = os.path.abspath(extension_dir)
    logger.info(f"ReVa extension directory: {extension_dir}")

    # Add extension to classpath
    extension_lib = os.path.join(extension_dir, "lib")
    extension_classes = os.path.join(extension_dir, "build", "classes", "java", "main")

    logger.info("Initializing pyghidra...")

    try:
        import pyghidra
    except ImportError:
        logger.error("pyghidra is not installed. Install it with: pip install pyghidra")
        sys.exit(1)

    # Configure pyghidra launcher
    launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()

    # Add ReVa extension to classpath
    if os.path.exists(extension_classes):
        logger.info(f"Adding ReVa classes to classpath: {extension_classes}")
        launcher.add_classpaths(extension_classes)

    # Add all JARs from lib directory
    if os.path.exists(extension_lib):
        import glob
        jars = glob.glob(os.path.join(extension_lib, "*.jar"))
        if jars:
            logger.info(f"Adding {len(jars)} JAR files from lib directory")
            for jar in jars:
                launcher.add_classpaths(jar)

    # Start Ghidra
    logger.info("Starting Ghidra in headless mode...")
    launcher.start()

    logger.info("Ghidra initialized successfully")

    # Import Java classes after Ghidra is initialized
    try:
        from reva.server import HeadlessRevaLauncher
    except ImportError as e:
        logger.error(f"Failed to import HeadlessRevaLauncher: {e}")
        logger.error("Make sure the ReVa extension is built (run 'gradle build')")
        sys.exit(1)

    # Create and launch the ReVa server
    global launcher_instance
    logger.info(f"Creating ReVa launcher (host={args.host}, port={args.port})")
    launcher_instance = HeadlessRevaLauncher(args.host, args.port)

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Launching ReVa MCP server...")
    launcher_instance.launch()

    if not launcher_instance.isServerReady():
        logger.error("Failed to start MCP server")
        sys.exit(1)

    logger.info(f"ReVa MCP server is ready at http://{args.host}:{args.port}")

    # Open project if specified
    if args.project_dir and args.project_name:
        try:
            logger.info(f"Opening Ghidra project: {args.project_name} from {args.project_dir}")
            project = launcher_instance.openProject(args.project_dir, args.project_name)
            logger.info(f"Project opened: {project.getName()}")

            # Load specified programs
            if args.programs:
                for program_path in args.programs:
                    try:
                        logger.info(f"Loading program: {program_path}")
                        program = launcher_instance.openProgram(program_path)
                        logger.info(f"Program loaded: {program.getName()}")
                    except Exception as e:
                        logger.error(f"Failed to load program {program_path}: {e}")
            else:
                logger.info("No programs specified. Project opened but no programs loaded.")
                logger.info("Use MCP tools to interact with the project.")

        except Exception as e:
            logger.error(f"Failed to open project: {e}")
            launcher_instance.shutdown()
            sys.exit(1)

    logger.info("=" * 80)
    logger.info("ReVa MCP Server is running in headless mode")
    logger.info(f"Server URL: http://{args.host}:{args.port}")
    logger.info("Press Ctrl+C to stop the server")
    logger.info("=" * 80)

    # Keep the server running
    try:
        launcher_instance.waitForShutdown()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        logger.info("Shutting down...")
        launcher_instance.shutdown()
        logger.info("Goodbye!")


if __name__ == '__main__':
    main()
