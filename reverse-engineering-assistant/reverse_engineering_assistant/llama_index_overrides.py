from typing import Optional, Dict, List, Any, Sequence
from llama_index.prompts.base import PromptTemplate
from llama_index.selectors.prompts import SingleSelectPrompt
from llama_index.output_parsers.selection import SelectionOutputParser, _escape_curly_braces, FORMAT_STR
from llama_index.agent.react.output_parser import ReActOutputParser
from llama_index.agent.react.types import BaseReasoningStep
from llama_index.agent.react.formatter import ReActChatFormatter

from llama_index.callbacks.base_handler import BaseCallbackHandler
from llama_index.callbacks.schema import CBEventType, EventPayload

from llama_index.agent.react.types import BaseReasoningStep, ObservationReasoningStep
from llama_index.llms.base import ChatMessage, MessageRole
from llama_index.tools import BaseTool



from llama_index.agent.react.types import (
    ActionReasoningStep,
    BaseReasoningStep,
    ResponseReasoningStep,
)

import logging

logger = logging.getLogger('reverse_engineering_assistant.llama_index_overrides')

REVA_SELECTION_OUTPUT_PARSER = """Some choices are given below. It is provided in a numbered list
(1 to {num_choices}),
where each item in the list corresponds to a summary.
---------------------
{context_list}
---------------------
Using only the choices above and not prior knowledge, return 
the choice that is most relevant to the question: '{query_str}'

{schema}

Select *only* one option. Return *only* JSON.
"""

class RevaSelectionOutputParser(SelectionOutputParser):
    def format(self, prompt_template: str) -> str:
        # We are running before the template is formatted, so we need to do a partial
        # then return a string that still contains some format fields
        # {query_str}, {num_choices}, {context_list}

        # Here we are working around the following bug: https://github.com/jerryjliu/llama_index/issues/7706
        # The multiple curly braces make life hard here, so we just find/replace :(
        template = prompt_template.replace('{schema}', _escape_curly_braces(FORMAT_STR))
        return template
    
class RevaReActChatFormatter(ReActChatFormatter):
    system_header = """
You have access to the following tools:
{tool_desc}

You must follow these instructions:
Always select one of the above tools based on the user query
If a tool is found, you must respond in the JSON format matching the following schema:
{{
    "thought": "<reason for using the tool>",
    "tool": "<name of the selected tool>",
    "tool_input": <parameters for the selected tool, matching the tool's JSON schema
}}
You will respond with **only one tool** at a time
If there is no tool that match the user request, you will respond with empty json.
Output **valid** JSON!
Do not add any additional Notes or Explanations
"""

    def tools_to_dict(self, tools: Sequence[BaseTool]) -> Sequence[Dict[str, str]]:
        """Convert our tool list to a dictionary, suitable for JSON output."""
        tool_list = []
        for tool in tools:
            tool_entry = {
                "name": tool.metadata.name,
                "description": tool.metadata.description,
                "parameters": tool.metadata.fn_schema_str,
            }
            tool_list.append(tool_entry)
        return tool_list

    def format(
            self,
            tools: Sequence[BaseTool],
            chat_history: List[ChatMessage],
            current_reasoning: Optional[List[BaseReasoningStep]] = None,
        ) -> List[ChatMessage]:
            """Format chat history into list of ChatMessage."""
            current_reasoning = current_reasoning or []

            tool_descs_str = self.tools_to_dict(tools)

            fmt_sys_header = self.system_header.format(
                tool_desc=tool_descs_str,
                tool_names=", ".join([tool.metadata.get_name() for tool in tools]),
            )

            # format reasoning history as alternating user and assistant messages
            # where the assistant messages are thoughts and actions and the user
            # messages are observations
            reasoning_history = []
            for reasoning_step in current_reasoning:
                if isinstance(reasoning_step, ObservationReasoningStep):
                    message = ChatMessage(
                        role=MessageRole.USER,
                        content=reasoning_step.get_content(),
                    )
                else:
                    message = ChatMessage(
                        role=MessageRole.ASSISTANT,
                        content=reasoning_step.get_content(),
                    )
                reasoning_history.append(message)

            return [
                ChatMessage(role=MessageRole.SYSTEM, content=fmt_sys_header),
                *chat_history,
                *reasoning_history,
            ]



class RevaReActOutputParser(ReActOutputParser):
    logger: logging.Logger = logging.getLogger('reverse_engineering_assistant.RevaReActOutputParser')
    def parse(self, output: str, is_streaming: bool = False) -> BaseReasoningStep:
        """ We need to fix the output from the LLM to match the expected outout from the parser.
        The parser is very strict.
        """

        import json
        try:
            step = json.loads(output)
            self.logger.warning(f"Tool: {step}")
            if 'tool' in step:
                return ActionReasoningStep(
                    thought=step.get('thought', '(Implicit) I can answer without any more tools!'),
                    action=step['tool'],
                    action_input=step['tool_input'],
                    is_streaming=is_streaming,
                )
            else:
                return ResponseReasoningStep(
                    thought=step.get('thought', '(Implicit) I can answer without any more tools!'),
                    response=str(step),
                    is_streaming=is_streaming,
                )

        except json.JSONDecodeError:
            return ResponseReasoningStep(
                thought=step.get('thought', '(Implicit) I can answer without any more tools!'),
                response=step[output],
                is_streaming=is_streaming,
            )



        # Now lets output either a observation reasoning step
        

class RevaLLMLog(BaseCallbackHandler):
    """Callback handler for printing llms inputs/outputs."""
    logger: logging.Logger
    def __init__(self) -> None:
        self.logger = logging.Logger('reverse_engineering_assistant.RevaLLMLog')
        self.logger.setLevel(logging.DEBUG)
        super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        return
    
    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        return
    
    def _log_llm_event(self, payload: Dict) -> None:
        from llama_index.llms import ChatMessage
        #self.logger.debug(f"{payload}")
        pass

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        return event_id
    
    def on_event_end(
        self,
        event_type: CBEventType,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Count the LLM or Embedding tokens as needed."""
        self.logger.debug(f"Event type: {event_type}, payload: {payload}")
        if event_type == CBEventType.LLM and payload is not None:
            self._log_llm_event(payload)

