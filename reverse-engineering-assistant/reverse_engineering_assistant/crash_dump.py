import logging
import traceback
from typing import Optional
from assistant import ReverseEngineeringAssistant
import datetime
from pathlib import Path

from langchain_core.messages import BaseMessage

import textwrap
import sys

def crash_dump(
        e: Optional[Exception] = None,
        assistant: Optional[ReverseEngineeringAssistant] = None,
    ) -> str:
    """Generate a crash dump of ReVa state and attempt to explain the issue"""
    logger = logging.getLogger("reva.crash_dump")
    # NOTE: In this block we will try to diagnose our own failure
    # we should not hit this case unless there is a bad error and we
    # will use the LLM to format a message and save a crash log.

    if not e:
        # If the developer did not give an exception
        # we can try to find it.
        exception_type, exception_value, _ = sys.exc_info()
        if exception_value:
            e = exception_value # type: ignore

    date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

    generic_crash_path = Path.home() / ".cache" / "reverse-engineering-assistant" / "crash"

    if assistant:
        crash_path = assistant.project.project_path / "crash"
    else:
         crash_path = generic_crash_path
    crash_path.mkdir(parents=True, exist_ok=True)
    generic_crash_path.mkdir(parents=True, exist_ok=True)

    crash_dump_name = f"reva-crash-{date}.log.md"
    crash_dump_chat_log_name = f"reva-crash-{date}.chat.log"

    # Begin building the crash report content
    analysis = textwrap.dedent(
            f"""
            ## **ReVa could not complete your request.**
            Logs have been saved to `{crash_path / crash_dump_name}`.

            Time: {date}
        """)
    if e:
        # If we have an exception, add it to the crash report
        analysis += textwrap.dedent(f"""
            ### Exception:
            ```
            {e}
            ```
        """)

    analysis += textwrap.dedent(f"""
            ### Traceback:
            ```
            {traceback.format_exc()}
            ```
        """)

    if assistant:
        # Get details about the assistant for debugging
        # also save the chat log
        analysis += textwrap.dedent(f"""
            ### Assistant details:
            - RevaModel: {assistant.llm}
            - Loaded tools: {assistant.tools}
        """)
        for path in [crash_path, generic_crash_path]:
            path.mkdir(parents=True, exist_ok=True)
            path.joinpath(crash_dump_chat_log_name).write_text(assistant.chat_history)

    if assistant:
        try:
            # Let's try to explain the exception using the model
            # loaded in the assistant.
            # We need to take away the tools, so she doesn't try to answer
            # by reverse engineering the program...
            answer: BaseMessage = assistant.llm.invoke(
                textwrap.dedent(f"""
                    You are ReVa, the reverse engineering assisstant. During your execution you threw an exception.
                    Your logs are located in the file {crash_path / crash_dump_name}.
                    {f"Can you explain the error: {e}" if e else ""}
                    A traceback of the error is:
                    {traceback.format_exc()}
                """)
            )
            answer_content: str
            if isinstance(answer, str):
                # This only happened in older versions of langchain
                answer_content = answer
            elif isinstance(answer, dict):
                answer_content = answer["output"]
            elif isinstance(answer, BaseMessage):
                answer_content = str(answer.content)
            else:
                raise ValueError(f"Unexpected answer type: {type(answer)}")
            analysis += textwrap.dedent(f"""
                # ReVa's analysis:
                > She has examined the exception:
                ```
                {e if e else "No exception provided"}

                {traceback.format_exc()}
                ```
                ## ReVa's debugging notes:
                {answer_content}
            """)
        except Exception as e:
                logger.exception(f"Failed to query engine: {e}")

    # Finally, save the crash dump
    for path in [generic_crash_path, crash_path]:
        path.mkdir(parents=True, exist_ok=True)
        path.joinpath(crash_dump_name).write_text(analysis)

    return analysis
