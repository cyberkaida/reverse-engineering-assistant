from typing import Optional, Dict, List, Any
from llama_index.prompts.base import PromptTemplate
from llama_index.selectors.prompts import SingleSelectPrompt
from llama_index.output_parsers.selection import SelectionOutputParser, _escape_curly_braces, FORMAT_STR
from llama_index.agent.react.output_parser import ReActOutputParser
from llama_index.agent.react.types import BaseReasoningStep
from llama_index.agent.react.formatter import ReActChatFormatter

from llama_index.callbacks.base_handler import BaseCallbackHandler
from llama_index.callbacks.schema import CBEventType, EventPayload

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
    pass


class RevaReActOutputParser(ReActOutputParser):
    def parse(self, output: str, is_streaming: bool = False) -> BaseReasoningStep:
        """ We need to fix the output from the LLM to match the expected outout from the parser.
        The parser is very strict.
        """

        # First examine the output for the action the LLM wants to take
        # and make sure *only* the function name is in the line. We will do this with
        # a regular expression.
        original_output = output
        import re

        if 'Thought:' in output:
            thought = re.search(r'Thought: (.*?)(Action:|Answer:)', output, re.DOTALL).group(1).strip()
            
            assert thought

            if 'Action:' in output:
                action = re.search(r'Action: ([a-zA-Z_0-9]+).*?Action Input:', output, re.DOTALL).group(1).strip()
                action_input = re.search(r'Action Input: (\{.*?\})', output, re.DOTALL).group(1).strip()

                # If the LLM chooses to take an action, we will clean it's output.
                assert action_input.startswith('{') and action_input.endswith('}'), f"Action input is not a JSON object: {action_input}"    
                output = f"Thought: {thought}\nAction: {action}\nAction Input: {action_input}\n"            

            # Now we have cleaned the output, we will pass it to the parser
            if output != original_output:
                logger.debug(f"Replaced output from LLM: {original_output} with {output}")
        return super().parse(output, is_streaming)

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
        self.logger.debug(f"LLM payload: {payload}")

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

