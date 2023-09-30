from llama_index.prompts.base import PromptTemplate
from llama_index.selectors.prompts import SingleSelectPrompt
from llama_index.output_parsers.selection import SelectionOutputParser, _escape_curly_braces, FORMAT_STR

REVA_SELECTION_OUTPUT_PARSER = """<<SYS>>
<</SYS>>
[INST]
Some choices are given below. It is provided in a numbered list
(1 to {num_choices}),
where each item in the list corresponds to a summary.
---------------------
{context_list}
---------------------
Using only the choices above and not prior knowledge, return 
the choice that is most relevant to the question: '{query_str}'

{schema}

Select *only* one option. Return *only* JSON.
[/INST]
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

